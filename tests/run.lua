local Core = require("ansible-vault.core")
local Popup = require("ansible-vault.popup")
local Vault = require("ansible-vault")
local uv = vim.uv or vim.loop

local failures = 0
local original_notify = vim.notify
vim.notify = function() end

local function assert_equal(actual, expected)
    assert(vim.deep_equal(actual, expected), ("expected %s, got %s"):format(vim.inspect(expected), vim.inspect(actual)))
end

local function with_override(target, key, value, callback)
    local original = target[key]
    target[key] = value
    local results = { pcall(callback) }
    target[key] = original
    assert(results[1], results[2])
    return unpack(results, 2)
end

local function with_temp_dir(callback)
    local path = vim.fn.tempname()
    assert(vim.fn.mkdir(path, "p") == 1)
    local results = { pcall(callback, path) }
    vim.fn.delete(path, "rf")
    assert(results[1], results[2])
    return unpack(results, 2)
end

local function test(name, callback)
    local ok, err = xpcall(callback, debug.traceback)
    if ok then
        print("ok - " .. name)
    else
        failures = failures + 1
        print("not ok - " .. name .. "\n" .. err)
    end
end

local ciphertext = {
    "$ANSIBLE_VAULT;1.1;AES256",
    "616263",
}

test("atomically replaces ciphertext and preserves permissions", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "vault.yml")
        assert(vim.fn.writefile({ "old" }, path) == 0)
        assert(uv.fs_chmod(path, tonumber("640", 8)))

        with_override(Core, "encrypt_content", function()
            return ciphertext
        end, function()
            local ok, err = Core.encrypt_file_with_content({ debug = false }, path, "plain")
            assert(ok, err)
        end)

        assert_equal(vim.fn.readfile(path), ciphertext)
        assert_equal(uv.fs_stat(path).mode % 512, tonumber("640", 8))
    end)
end)

test("rejects invalid ciphertext without replacing the original", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "vault.yml")
        assert(vim.fn.writefile({ "original" }, path) == 0)

        with_override(Core, "encrypt_content", function()
            return { "not a vault" }
        end, function()
            local ok, err = Core.encrypt_file_with_content({ debug = false }, path, "plain")
            assert(not ok and err:match("invalid Ansible Vault ciphertext"), err)
        end)

        assert_equal(vim.fn.readfile(path), { "original" })
    end)
end)

test("keeps symlinks intact while replacing their targets", function()
    with_temp_dir(function(dir)
        local target = vim.fs.joinpath(dir, "target.yml")
        local link = vim.fs.joinpath(dir, "vault.yml")
        assert(vim.fn.writefile({ "old" }, target) == 0)
        assert(uv.fs_symlink(target, link))

        with_override(Core, "encrypt_content", function()
            return ciphertext
        end, function()
            local ok, err = Core.encrypt_file_with_content({ debug = false }, link, "plain")
            assert(ok, err)
        end)

        assert_equal(uv.fs_lstat(link).type, "link")
        assert_equal(vim.fn.readfile(target), ciphertext)
    end)
end)

test("rejects non-regular symlink targets", function()
    with_temp_dir(function(dir)
        local target = vim.fs.joinpath(dir, "directory")
        local link = vim.fs.joinpath(dir, "vault.yml")
        assert(vim.fn.mkdir(target) == 1)
        assert(uv.fs_symlink(target, link))

        local ok, err = Core.encrypt_file_with_content({ debug = false }, link, "plain")
        assert(not ok and err:match("not a regular file"), err)
        assert_equal(uv.fs_lstat(link).type, "link")
    end)
end)

test("refuses to replace externally changed vault files", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "vault.yml")
        assert(vim.fn.writefile({ "original" }, path) == 0)

        with_override(Core, "encrypt_content", function()
            assert(vim.fn.writefile({ "external change" }, path) == 0)
            return ciphertext
        end, function()
            local ok, err = Core.encrypt_file_with_content({ debug = false }, path, "plain")
            assert(not ok and err:match("changed during encryption"), err)
        end)

        assert_equal(vim.fn.readfile(path), { "external change" })
    end)
end)

test("refuses to replace hard-linked vault files", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "vault.yml")
        local link = vim.fs.joinpath(dir, "second-name.yml")
        assert(vim.fn.writefile({ "original" }, path) == 0)
        assert(uv.fs_link(path, link))

        local ok, err = Core.encrypt_file_with_content({ debug = false }, path, "plain")
        assert(not ok and err:match("multiple hard links"), err)
        assert_equal(vim.fn.readfile(link), { "original" })
    end)
end)

test("uses and removes a mode-0600 one-time password file", function()
    local password_path
    local password_mode
    local password_content

    with_override(vim, "system", function(args)
        for i, arg in ipairs(args) do
            if arg == "--vault-password-file" then
                password_path = args[i + 1]
                break
            end
        end
        assert(password_path)
        password_mode = uv.fs_stat(password_path).mode % 512
        password_content = vim.fn.readfile(password_path)
        return {
            wait = function()
                return {
                    code = 0,
                    stdout = "value: !vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          616263\n",
                    stderr = "",
                }
            end,
        }
    end, function()
        local lines, err = Core.encrypt_content({ debug = false, vault_executable = "ansible-vault" }, "plain", {
            password = "secret",
        })
        assert(lines, err)
        assert_equal(lines, ciphertext)
    end)

    assert_equal(password_mode, tonumber("600", 8))
    assert_equal(password_content, { "secret" })
    assert_equal(vim.fn.filereadable(password_path), 0)
end)

test("binds one-time passwords to the selected vault ID", function()
    local command
    local password_path

    with_override(vim, "system", function(args)
        command = args
        for _, arg in ipairs(args) do
            password_path = password_path or arg:match("^prod@(.+)$")
        end
        return {
            wait = function()
                return {
                    code = 0,
                    stdout = "value: !vault |\n          $ANSIBLE_VAULT;1.2;AES256;prod\n          616263\n",
                    stderr = "",
                }
            end,
        }
    end, function()
        local lines, err = Core.encrypt_content({ debug = false, vault_executable = "ansible-vault" }, "plain", {
            encrypt_vault_id = "prod",
            password = "secret",
        })
        assert(lines, err)
    end)

    assert(vim.list_contains(command, "--encrypt-vault-id"))
    assert(vim.list_contains(command, "--vault-id"))
    assert(not vim.list_contains(command, "--vault-password-file"))
    assert(password_path)
    assert_equal(vim.fn.filereadable(password_path), 0)
end)

test("removes one-time password files after process errors", function()
    local password_path

    with_override(vim, "system", function(args)
        for i, arg in ipairs(args) do
            if arg == "--vault-password-file" then
                password_path = args[i + 1]
            end
        end
        error("process construction failed")
    end, function()
        local lines, err = Core.encrypt_content({ debug = false, vault_executable = "ansible-vault" }, "plain", {
            password = "secret",
        })
        assert(not lines and err:match("Failed to run ansible%-vault"), err)
    end)

    assert(password_path)
    assert_equal(vim.fn.filereadable(password_path), 0)
end)

test("refuses disk changes that predate EncryptFile", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "plain.yml")
        assert(vim.fn.writefile({ "loaded content" }, path) == 0)
        vim.cmd("edit " .. vim.fn.fnameescape(path))
        local bufnr = vim.api.nvim_get_current_buf()
        vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, { "unsaved content" })
        local fd = assert(uv.fs_open(path, "w", tonumber("600", 8)))
        assert(uv.fs_write(fd, "external content\nwith a different size\n", 0))
        assert(uv.fs_close(fd))
        local changed_time = os.time() + 2
        assert(uv.fs_utime(path, changed_time, changed_time))
        local encrypted = false

        with_override(Core, "encrypt_file_with_content", function()
            encrypted = true
            return true
        end, function()
            Vault.encrypt_current_file(bufnr)
        end)

        assert(not encrypted)
        assert_equal(vim.fn.readfile(path), { "external content", "with a different size" })
        vim.cmd("bwipeout!")
    end)
end)

test("encrypts the current unsaved buffer instead of stale disk content", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "plain.yml")
        assert(vim.fn.writefile({ "disk content" }, path) == 0)
        vim.cmd("edit " .. vim.fn.fnameescape(path))
        local bufnr = vim.api.nvim_get_current_buf()
        local buffer_path = vim.api.nvim_buf_get_name(bufnr)
        vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, { "unsaved content" })

        local captured_plaintext
        with_override(Core, "encrypt_file_with_content", function(_, output_path, plaintext)
            captured_plaintext = plaintext
            assert_equal(output_path, buffer_path)
            assert(vim.fn.writefile(ciphertext, path) == 0)
            return true
        end, function()
            Vault.encrypt_current_file(bufnr)
            assert(vim.wait(1000, function()
                return captured_plaintext ~= nil
            end))
        end)

        assert_equal(captured_plaintext, "unsaved content\n")
        assert_equal(vim.api.nvim_buf_get_lines(bufnr, 0, -1, false), ciphertext)
        assert(not vim.bo[bufnr].modified)
        vim.cmd("bwipeout!")
    end)
end)

test("cancels async encryption retries after destination changes", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "plain.yml")
        assert(vim.fn.writefile({ "disk content" }, path) == 0)
        vim.cmd("edit " .. vim.fn.fnameescape(path))
        local bufnr = vim.api.nvim_get_current_buf()
        local select_callback
        local attempts = 0

        with_override(vim.ui, "select", function(_, _, callback)
            select_callback = callback
        end, function()
            with_override(Core, "encrypt_file_with_content", function()
                attempts = attempts + 1
                return nil, "The vault-ids prod are available to encrypt"
            end, function()
                Vault.encrypt_current_file(bufnr)
                assert(vim.wait(1000, function()
                    return select_callback ~= nil
                end))
                assert(vim.fn.writefile({ "external change" }, path) == 0)
                select_callback("prod")
            end)
        end)

        assert_equal(attempts, 1)
        assert_equal(vim.fn.readfile(path), { "external change" })
        vim.cmd("bwipeout!")
    end)
end)

test("does not reload over buffer changes made during encryption", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "plain.yml")
        assert(vim.fn.writefile({ "disk content" }, path) == 0)
        vim.cmd("edit " .. vim.fn.fnameescape(path))
        local bufnr = vim.api.nvim_get_current_buf()
        vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, { "encryption snapshot" })

        with_override(Core, "encrypt_file_with_content", function()
            vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, { "newer buffer content" })
            assert(vim.fn.writefile(ciphertext, path) == 0)
            return true
        end, function()
            Vault.encrypt_current_file(bufnr)
            assert(vim.wait(1000, function()
                return vim.api.nvim_buf_get_lines(bufnr, 0, 1, false)[1] == "newer buffer content"
            end))
        end)

        assert_equal(vim.api.nvim_buf_get_lines(bufnr, 0, -1, false), { "newer buffer content" })
        assert(vim.bo[bufnr].modified)
        assert_equal(vim.fn.readfile(path), ciphertext)
        vim.cmd("bwipeout!")
    end)
end)

test("popup saves reload the source and restore the original window", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "vault.yml")
        assert(vim.fn.writefile({ "$ANSIBLE_VAULT;1.1;AES256", "old" }, path) == 0)
        vim.cmd("edit " .. vim.fn.fnameescape(path))
        local source_buf = vim.api.nvim_get_current_buf()
        local source_win = vim.api.nvim_get_current_win()
        local buffer_path = vim.api.nvim_buf_get_name(source_buf)
        local captured_opts

        with_override(Core, "encrypt_file_with_content", function(_, output_path, plaintext, opts)
            assert_equal(output_path, buffer_path)
            assert_equal(plaintext, "updated plaintext")
            captured_opts = opts
            assert(vim.fn.writefile(ciphertext, path) == 0)
            return true
        end, function()
            Popup.open({ debug = false }, {
                bufnr = source_buf,
                file_path = buffer_path,
                vault_type = Core.VaultType.file,
                vault_name = "vault.yml",
                decrypted_value = "old plaintext",
                password = "one-time",
            })
            local popup_buf = vim.api.nvim_get_current_buf()
            vim.api.nvim_buf_set_lines(popup_buf, 0, -1, false, { "updated plaintext" })
            local save = vim.fn.maparg("<CR>", "n", false, true).callback
            assert(type(save) == "function")
            save()
        end)

        assert_equal(captured_opts.password, "one-time")
        assert_equal(vim.api.nvim_get_current_win(), source_win)
        assert_equal(vim.api.nvim_buf_get_lines(source_buf, 0, -1, false), ciphertext)
        assert(not vim.bo[source_buf].modified)
        vim.cmd("bwipeout!")
    end)
end)

test("popup preserves a whole-file vault's final newline", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "vault.yml")
        assert(vim.fn.writefile({ "$ANSIBLE_VAULT;1.1;AES256", "old" }, path) == 0)
        vim.cmd("edit " .. vim.fn.fnameescape(path))
        local source_buf = vim.api.nvim_get_current_buf()
        local buffer_path = vim.api.nvim_buf_get_name(source_buf)
        local captured_plaintext

        with_override(Core, "encrypt_file_with_content", function(_, _, plaintext)
            captured_plaintext = plaintext
            assert(vim.fn.writefile(ciphertext, path) == 0)
            return true
        end, function()
            Popup.open({ debug = false }, {
                bufnr = source_buf,
                file_path = buffer_path,
                vault_type = Core.VaultType.file,
                vault_name = "vault.yml",
                decrypted_value = "old plaintext\n",
            })
            local popup_buf = vim.api.nvim_get_current_buf()
            vim.api.nvim_buf_set_lines(popup_buf, 0, -1, false, { "updated plaintext" })
            vim.fn.maparg("<CR>", "n", false, true).callback()
        end)

        assert_equal(captured_plaintext, "updated plaintext\n")
        vim.cmd("bwipeout!")
    end)
end)

test("popup does not reload over source changes made during encryption", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "vault.yml")
        assert(vim.fn.writefile({ "$ANSIBLE_VAULT;1.1;AES256", "old" }, path) == 0)
        vim.cmd("edit " .. vim.fn.fnameescape(path))
        local source_buf = vim.api.nvim_get_current_buf()
        local buffer_path = vim.api.nvim_buf_get_name(source_buf)

        with_override(Core, "encrypt_file_with_content", function()
            vim.api.nvim_buf_set_lines(source_buf, 0, -1, false, { "newer source content" })
            assert(vim.fn.writefile(ciphertext, path) == 0)
            return true
        end, function()
            Popup.open({ debug = false }, {
                bufnr = source_buf,
                file_path = buffer_path,
                vault_type = Core.VaultType.file,
                vault_name = "vault.yml",
                decrypted_value = "old plaintext",
            })
            local popup_buf = vim.api.nvim_get_current_buf()
            vim.api.nvim_buf_set_lines(popup_buf, 0, -1, false, { "updated plaintext" })
            vim.fn.maparg("<CR>", "n", false, true).callback()
        end)

        assert_equal(vim.api.nvim_buf_get_lines(source_buf, 0, -1, false), { "newer source content" })
        assert(vim.bo[source_buf].modified)
        assert_equal(vim.fn.readfile(path), ciphertext)
        vim.cmd("bwipeout!")
    end)
end)

test("popup ignores vault-ID callbacks after it closes", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "vault.yml")
        assert(vim.fn.writefile({ "$ANSIBLE_VAULT;1.1;AES256", "old" }, path) == 0)
        vim.cmd("edit " .. vim.fn.fnameescape(path))
        local source_buf = vim.api.nvim_get_current_buf()
        local buffer_path = vim.api.nvim_buf_get_name(source_buf)
        local select_callback
        local attempts = 0
        local params = {
            bufnr = source_buf,
            file_path = buffer_path,
            vault_type = Core.VaultType.file,
            vault_name = "vault.yml",
            decrypted_value = "old plaintext",
            password = "one-time",
        }

        with_override(vim.ui, "select", function(_, _, callback)
            select_callback = callback
        end, function()
            with_override(Core, "encrypt_file_with_content", function()
                attempts = attempts + 1
                return nil, "The vault-ids prod are available to encrypt"
            end, function()
                Popup.open({ debug = false }, params)
                local popup_buf = vim.api.nvim_get_current_buf()
                vim.api.nvim_buf_set_lines(popup_buf, 0, -1, false, { "updated plaintext" })
                vim.fn.maparg("<CR>", "n", false, true).callback()
                assert(vim.wait(1000, function()
                    return select_callback ~= nil
                end))
                vim.fn.maparg("q", "n", false, true).callback()
                select_callback("prod")
            end)
        end)

        assert_equal(attempts, 1)
        assert_equal(params.password, nil)
        vim.cmd("bwipeout!")
    end)
end)

test("popup refuses to overwrite a concurrently changed source", function()
    with_temp_dir(function(dir)
        local path = vim.fs.joinpath(dir, "vault.yml")
        local original = { "$ANSIBLE_VAULT;1.1;AES256", "old" }
        assert(vim.fn.writefile(original, path) == 0)
        vim.cmd("edit " .. vim.fn.fnameescape(path))
        local source_buf = vim.api.nvim_get_current_buf()
        local buffer_path = vim.api.nvim_buf_get_name(source_buf)
        local encrypted = false

        with_override(Core, "encrypt_file_with_content", function()
            encrypted = true
            return true
        end, function()
            Popup.open({ debug = false }, {
                bufnr = source_buf,
                file_path = buffer_path,
                vault_type = Core.VaultType.file,
                vault_name = "vault.yml",
                decrypted_value = "old plaintext",
            })
            local popup_buf = vim.api.nvim_get_current_buf()
            vim.api.nvim_buf_set_lines(source_buf, 0, -1, false, { "concurrent change" })
            vim.api.nvim_buf_set_lines(popup_buf, 0, -1, false, { "updated plaintext" })
            local save = vim.fn.maparg("<CR>", "n", false, true).callback
            save()

            assert(not encrypted)
            assert(vim.api.nvim_buf_is_valid(popup_buf))
            local cancel = vim.fn.maparg("q", "n", false, true).callback
            cancel()
        end)

        assert_equal(vim.fn.readfile(path), original)
        vim.cmd("bwipeout!")
    end)
end)

vim.notify = original_notify
if failures > 0 then
    print(("%d test(s) failed"):format(failures))
    vim.cmd("cquit 1")
else
    print("all tests passed")
    vim.cmd("qa!")
end
