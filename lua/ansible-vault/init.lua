---@diagnostic disable: undefined-global
local Core = require("ansible-vault.core")
local Popup = require("ansible-vault.popup")

local M = {}
local uv = vim.uv or vim.loop

M.config = {
    vault_password_file = nil,
    ansible_cfg_directory = nil,
    vault_executable = "ansible-vault",
    debug = false,
}

local vault_buffers = {}

function M.setup(opts)
    vim.validate({ opts = { opts, "table", true } })
    M.config = vim.tbl_deep_extend("force", M.config, opts or {})
    local group = vim.api.nvim_create_augroup("AnsibleVault", { clear = true })
    vim.api.nvim_create_autocmd({ "BufDelete" }, {
        group = group,
        callback = function(args)
            vault_buffers[args.buf] = nil
        end,
    })
end

-- Resolve the directory containing ansible.cfg by walking upward from file_path.
-- If M.config.ansible_cfg_directory is set, that takes precedence.
-- Returns (dir, cfg_file_path) so callers can also parse the cfg if needed.
local function resolve_ansible_cfg_for_file(file_path)
    if M.config.ansible_cfg_directory and M.config.ansible_cfg_directory ~= "" then
        local dir = vim.fn.expand(M.config.ansible_cfg_directory)
        local cfg_path = dir .. "/ansible.cfg"
        if vim.fn.filereadable(cfg_path) == 1 then
            return dir, cfg_path
        end
        return dir, nil
    end
    if not file_path or file_path == "" then
        return nil, nil
    end
    local start_dir = vim.fs.dirname(file_path)
    local matches = vim.fs.find({ "ansible.cfg", ".ansible.cfg" }, {
        upward = true,
        path = start_dir,
        type = "file",
        limit = 1,
    })
    local found = (matches and matches[1]) or nil
    if found then
        return vim.fs.dirname(found), found
    end
    return nil, nil
end

-- Build a resolved config by auto-detecting ansible.cfg directory and vault_password_file.
local function resolve_config_for_file(file_path)
    local resolved_dir, cfg_file = resolve_ansible_cfg_for_file(file_path)
    local overrides = {}
    if resolved_dir and (not M.config.ansible_cfg_directory or M.config.ansible_cfg_directory == "") then
        overrides.ansible_cfg_directory = resolved_dir
    end
    if cfg_file and not M.config.vault_password_file then
        local pw_file = Core.parse_vault_password_file_from_cfg(cfg_file)
        if pw_file then
            overrides.vault_password_file = pw_file
        end
    end
    if next(overrides) then
        return vim.tbl_deep_extend("force", {}, M.config, overrides)
    end
    return M.config
end

function M.vault_access(bufnr)
    bufnr = bufnr or vim.api.nvim_get_current_buf()
    local file_path = vim.api.nvim_buf_get_name(bufnr)
    if file_path == "" then
        vim.notify("Cannot access vault without a file path", vim.log.levels.ERROR)
        return
    end

    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local vault_block = Core.find_inline_vault_block_at_cursor(lines)
    local vault_type = Core.VaultType.inline
    ---@type string
    local vault_name = vault_block and vault_block.key or file_path

    vault_buffers[bufnr] = true
    local cfg = resolve_config_for_file(file_path)

    if not vault_block then
        local file_is_vault = Core.check_is_file_vault(cfg, file_path)
        if file_is_vault then
            if vim.bo[bufnr].modified then
                vim.notify("Save or discard source-buffer changes before opening this vault", vim.log.levels.WARN)
                return
            end
            vault_type = Core.VaultType.file
            vault_name = vim.fs.basename(file_path)
        else
            vim.notify("No vault found at cursor position", vim.log.levels.WARN)
            return
        end
    end

    Core.debug(cfg, string.format("access vault_type=%s file=%s", vault_type, file_path))

    local decrypted_value, err
    if vault_type == Core.VaultType.inline then
        if not vault_block then
            vim.notify("Internal error: missing vault block for inline vault", vim.log.levels.ERROR)
            return
        end
        decrypted_value, err = Core.decrypt_inline_content(cfg, vault_block.vault_content)
    else
        decrypted_value, err = Core.decrypt_file_vault(cfg, file_path)
    end
    if not decrypted_value then
        -- Prompt for one-time password and retry once
        local function retry_with_password()
            -- Use secure hidden input
            local pw = vim.fn.inputsecret("Vault password (one-time): ")
            if not pw or pw == "" then
                vim.notify("Decryption cancelled (no password provided)", vim.log.levels.WARN)
                return
            end
            local retry_value, retry_err
            if vault_type == Core.VaultType.inline then
                if not vault_block or not vault_block.vault_content then
                    vim.notify("Internal error: missing vault block for inline vault", vim.log.levels.ERROR)
                    return
                end
                retry_value, retry_err = Core.decrypt_inline_content(cfg, vault_block.vault_content, { password = pw })
            else
                retry_value, retry_err = Core.decrypt_file_vault(cfg, file_path, { password = pw })
            end
            if not retry_value then
                vim.notify(
                    "Failed to decrypt with provided password: " .. (retry_err or "unknown error"),
                    vim.log.levels.ERROR
                )
                return
            end
            Popup.open(cfg, {
                bufnr = bufnr,
                file_path = file_path,
                vault_type = vault_type,
                vault_name = vault_name,
                decrypted_value = retry_value,
                vault_block = vault_block,
                password = pw,
            })
        end
        -- Prefer prompting only on auth-related failures; best effort check
        if err and (err:match("[Pp]assword") or err:match("[Vv]ault")) then
            pcall(vim.cmd, "stopinsert")
            vim.schedule(retry_with_password)
            return
        end
        vim.notify("Failed to decrypt " .. vault_name .. ": " .. (err or "unknown error"), vim.log.levels.ERROR)
        return
    end
    Core.debug(cfg, string.format("decrypted length=%d", #decrypted_value))

    Popup.open(cfg, {
        bufnr = bufnr,
        file_path = file_path,
        vault_type = vault_type,
        vault_name = vault_name,
        decrypted_value = decrypted_value,
        vault_block = vault_block,
    })
end

local function encrypt_checked_buffer(bufnr, file_path)
    local cfg = resolve_config_for_file(file_path)
    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    if lines[1] and lines[1]:match("^%$ANSIBLE_VAULT;") then
        vim.notify("File is already encrypted", vim.log.levels.WARN)
        return
    end

    local plaintext = table.concat(lines, "\n")
    if vim.bo[bufnr].endofline then
        plaintext = plaintext .. "\n"
    end
    local changedtick = vim.api.nvim_buf_get_changedtick(bufnr)
    local function file_stamp()
        local stat, _, code = uv.fs_stat(file_path)
        if not stat then
            return code or "missing"
        end
        return table.concat({ stat.dev, stat.ino, stat.size, stat.mtime.sec, stat.mtime.nsec }, ":")
    end
    local destination_stamp = file_stamp()
    Core.debug(cfg, string.format("encrypt_current_file file=%s bytes=%d", file_path, #plaintext))

    local function buffer_is_unchanged()
        if not vim.api.nvim_buf_is_valid(bufnr) or vim.api.nvim_buf_get_name(bufnr) ~= file_path then
            vim.notify("Encryption cancelled because the source buffer is no longer available", vim.log.levels.WARN)
            return false
        end
        if vim.api.nvim_buf_get_changedtick(bufnr) ~= changedtick then
            vim.notify("Encryption cancelled because the source buffer changed", vim.log.levels.WARN)
            return false
        end
        if file_stamp() ~= destination_stamp then
            vim.notify("Encryption cancelled because the destination file changed", vim.log.levels.WARN)
            return false
        end
        return true
    end

    local function finish_encryption()
        vim.notify("File encrypted successfully", vim.log.levels.INFO)
        if not vim.api.nvim_buf_is_valid(bufnr) or vim.api.nvim_buf_get_name(bufnr) ~= file_path then
            vim.notify("File was encrypted, but its source buffer is no longer available", vim.log.levels.WARN)
            return
        end
        if vim.api.nvim_buf_get_changedtick(bufnr) ~= changedtick then
            vim.notify("File was encrypted, but its changed source buffer was not reloaded", vim.log.levels.WARN)
            return
        end
        local ok, err = pcall(vim.api.nvim_buf_call, bufnr, function()
            vim.cmd("silent keepalt edit!")
        end)
        if not ok then
            vim.notify("File was encrypted, but its buffer could not be reloaded: " .. err, vim.log.levels.ERROR)
        end
    end

    local try_encrypt
    try_encrypt = function(opts)
        opts = opts or {}
        if not buffer_is_unchanged() then
            return
        end

        local ok, err = Core.encrypt_file_with_content(cfg, file_path, plaintext, next(opts) and opts or nil)
        if ok then
            finish_encryption()
            return
        end

        local ids = Core.extract_encrypt_vault_ids(err or "")
        if ids and #ids > 0 and not opts.encrypt_vault_id then
            pcall(vim.cmd, "stopinsert")
            vim.schedule(function()
                vim.ui.select(ids, { prompt = "Select vault-id for file encryption" }, function(choice)
                    if not choice then
                        vim.notify("Encryption cancelled (no vault-id selected)", vim.log.levels.WARN)
                        return
                    end
                    try_encrypt(vim.tbl_extend("force", {}, opts, { encrypt_vault_id = choice }))
                end)
            end)
            return
        end

        if err and err:match("[Pp]assword") and not opts.password then
            pcall(vim.cmd, "stopinsert")
            vim.schedule(function()
                local password = vim.fn.inputsecret("Vault password (one-time): ")
                if not password or password == "" then
                    vim.notify("Encryption cancelled (no password provided)", vim.log.levels.WARN)
                    return
                end
                try_encrypt(vim.tbl_extend("force", {}, opts, { password = password }))
            end)
            return
        end

        vim.notify("Failed to encrypt file: " .. (err or "unknown error"), vim.log.levels.ERROR)
    end

    try_encrypt()
end

function M.encrypt_current_file(bufnr)
    bufnr = bufnr or vim.api.nvim_get_current_buf()
    local file_path = vim.api.nvim_buf_get_name(bufnr)
    if file_path == "" then
        vim.notify("Cannot encrypt without a file path", vim.log.levels.ERROR)
        return
    end

    local external_change = false
    local check_autocmd = vim.api.nvim_create_autocmd("FileChangedShell", {
        buffer = bufnr,
        once = true,
        callback = function()
            external_change = true
            vim.v.fcs_choice = ""
        end,
    })

    local checked, check_err = pcall(vim.api.nvim_buf_call, bufnr, function()
        -- `:checktime` invoked through the API is deferred; `:normal` gives it typed-command semantics.
        vim.cmd("silent normal! :checktime\r")
    end)
    pcall(vim.api.nvim_del_autocmd, check_autocmd)
    if not checked then
        vim.notify("Cannot check the destination file: " .. check_err, vim.log.levels.ERROR)
        return
    end
    if external_change then
        vim.notify("Encryption cancelled because the destination changed on disk", vim.log.levels.WARN)
        return
    end

    if not vim.api.nvim_buf_is_valid(bufnr) or vim.api.nvim_buf_get_name(bufnr) ~= file_path then
        vim.notify("Encryption cancelled because the source buffer is no longer available", vim.log.levels.WARN)
        return
    end

    if not vim.bo[bufnr].modified and vim.fn.filereadable(file_path) == 1 then
        local buffer_lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
        local disk_lines = vim.fn.readfile(file_path)
        if #disk_lines == 0 then
            disk_lines = { "" }
        end
        local binary_lines = vim.fn.readfile(file_path, "b")
        local disk_has_eol = binary_lines[#binary_lines] == ""
        if not vim.deep_equal(buffer_lines, disk_lines) or vim.bo[bufnr].endofline ~= disk_has_eol then
            vim.notify("Encryption cancelled because the destination changed on disk", vim.log.levels.WARN)
            return
        end
    end

    encrypt_checked_buffer(bufnr, file_path)
end

---Encrypt the YAML scalar value at cursor into an inline vault block
---@param bufnr? integer
function M.encrypt_inline_at_cursor(bufnr)
    bufnr = bufnr or vim.api.nvim_get_current_buf()
    local cursor = vim.api.nvim_win_get_cursor(0)
    local line_nr = cursor[1]
    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local line = lines[line_nr]
    if not line then
        return
    end

    -- Match `key: value` on a single line, ignoring existing !vault
    local indent, key, value = line:match("^(%s*)([%w_-]+):%s*(.-)%s*$")
    if not indent or not key or not value or value == "" or value:match("!vault") then
        vim.notify("No simple YAML scalar at cursor to encrypt", vim.log.levels.WARN)
        return
    end

    local function apply_inline_enc(vault_lines)
        local content_indent = indent .. "  "
        local new_header = string.format("%s%s: !vault |-", indent, key)
        local to_insert = {}
        for _, l in ipairs(vault_lines) do
            table.insert(to_insert, content_indent .. l)
        end
        -- Replace current line with header, then insert vault lines below
        vim.api.nvim_buf_set_lines(bufnr, line_nr - 1, line_nr, false, { new_header })
        vim.api.nvim_buf_set_lines(bufnr, line_nr, line_nr, false, to_insert)
        vim.notify("Inline value encrypted", vim.log.levels.INFO)
    end

    local cfg = resolve_config_for_file(vim.api.nvim_buf_get_name(bufnr))
    local vault_lines, err = Core.encrypt_content(cfg, value)
    if not vault_lines then
        local ids = Core.extract_encrypt_vault_ids(err or "")
        if ids and #ids > 0 then
            pcall(vim.cmd, "stopinsert")
            vim.schedule(function()
                vim.ui.select(ids, { prompt = "Select vault-id for inline encryption" }, function(choice)
                    if not choice then
                        vim.notify("Inline encryption cancelled", vim.log.levels.WARN)
                        return
                    end
                    local retry_lines, retry_err = Core.encrypt_content(cfg, value, { encrypt_vault_id = choice })
                    if not retry_lines then
                        vim.notify(retry_err or "Failed to encrypt inline value", vim.log.levels.ERROR)
                        return
                    end
                    apply_inline_enc(retry_lines)
                end)
            end)
            return
        end
        vim.notify(err or "Failed to encrypt inline value", vim.log.levels.ERROR)
        return
    end
    apply_inline_enc(vault_lines)
end
return M
