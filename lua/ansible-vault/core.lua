---@class AnsibleVaultConfig
---@field vault_password_file? string
---@field ansible_cfg_directory? string
---@field vault_executable string

---@alias VaultType "inline"|"file"

---@diagnostic disable: undefined-global
local Core = {}
local uv = vim.uv or vim.loop

-- Derive working directory and executable from provided config
local function get_cwd(config)
	if config and config.ansible_cfg_directory and config.ansible_cfg_directory ~= "" then
		return vim.fn.expand(config.ansible_cfg_directory)
	end
	return nil
end

local function get_executable(config)
	if config and config.vault_executable then
		return vim.fn.expand(config.vault_executable)
	end
	return "ansible-vault"
end

local function write_all(fd, content)
	local offset = 0
	while offset < #content do
		local written, err = uv.fs_write(fd, content:sub(offset + 1), offset)
		if not written or written == 0 then
			return nil, err or "write returned zero bytes"
		end
		offset = offset + written
	end
	return true
end

local function remove_file(path)
	local called, removed, err = pcall(uv.fs_unlink, path)
	if not called then
		return nil, tostring(removed)
	end
	if not removed then
		return nil, err or "failed to remove file"
	end
	return true
end

local function write_secure_file(path, content, mode, uid, gid)
	local fd, open_err = uv.fs_open(path, "wx", mode)
	if not fd then
		return nil, open_err or "failed to open file"
	end

	local ok, err = true, nil
	if uid and gid then
		ok, err = uv.fs_fchown(fd, uid, gid)
	end
	if ok then
		ok, err = uv.fs_fchmod(fd, mode)
	end
	if ok then
		ok, err = write_all(fd, content)
	end
	if ok then
		ok, err = uv.fs_fsync(fd)
	end
	local closed, close_err = uv.fs_close(fd)
	if not ok or not closed then
		remove_file(path)
		return nil, err or close_err or "failed to close file"
	end
	return true
end

local function with_temporary_password_file(password, callback)
	local path = vim.fn.tempname()
	local ok, err = write_secure_file(path, password .. "\n", tonumber("600", 8))
	if not ok then
		return nil, "Failed to create temporary password file: " .. (err or "unknown error")
	end

	local called, result = pcall(callback, path)
	local removed, remove_err = remove_file(path)
	if not called then
		local suffix = removed and "" or "; password-file cleanup failed: " .. remove_err
		return nil, "Failed to run ansible-vault: " .. tostring(result) .. suffix
	end
	if not removed then
		return nil, "Failed to remove temporary password file: " .. remove_err
	end
	return result
end

local function inspect_destination(file_path)
	local target_path = file_path
	local file_stat, stat_err, stat_code = uv.fs_lstat(file_path)
	if file_stat and file_stat.type == "link" then
		local resolved, resolve_err = uv.fs_realpath(file_path)
		if not resolved then
			return nil, "Failed to resolve vault symlink: " .. (resolve_err or "unknown error")
		end
		target_path = resolved
		file_stat, stat_err, stat_code = uv.fs_stat(target_path)
	end
	if not file_stat and stat_code and stat_code ~= "ENOENT" then
		return nil, "Failed to inspect vault file: " .. (stat_err or stat_code)
	end
	if file_stat and file_stat.type ~= "file" then
		return nil, "Vault path is not a regular file"
	end
	if file_stat and file_stat.nlink and file_stat.nlink > 1 then
		return nil, "Refusing to replace a vault file with multiple hard links"
	end

	local fingerprint
	if file_stat then
		fingerprint = table.concat({
			file_stat.dev,
			file_stat.ino,
			file_stat.size,
			file_stat.mtime.sec,
			file_stat.mtime.nsec,
		}, ":")
	end
	return {
		target_path = target_path,
		mode = file_stat and (file_stat.mode % 512) or tonumber("600", 8),
		uid = file_stat and file_stat.uid or nil,
		gid = file_stat and file_stat.gid or nil,
		fingerprint = fingerprint,
	}
end

local function atomic_replace(file_path, content, expected, operation)
	local temp_path = vim.fs.joinpath(
		vim.fs.dirname(expected.target_path),
		string.format(
			".%s.nvim-ansible-vault.%d.%s",
			vim.fs.basename(expected.target_path),
			vim.fn.getpid(),
			uv.hrtime()
		)
	)
	local wrote, write_err = write_secure_file(temp_path, content, tonumber("600", 8), expected.uid, expected.gid)
	if not wrote then
		return nil, "Failed to write replacement temporary file: " .. (write_err or "unknown error")
	end

	local current, inspect_err = inspect_destination(file_path)
	if not current or current.target_path ~= expected.target_path or current.fingerprint ~= expected.fingerprint then
		remove_file(temp_path)
		return nil, inspect_err or "Vault file changed during " .. operation .. "; refusing to overwrite it"
	end

	local permissions_set, permissions_err = uv.fs_chmod(temp_path, expected.mode)
	if not permissions_set then
		remove_file(temp_path)
		return nil, "Failed to preserve vault file permissions: " .. (permissions_err or "unknown error")
	end

	local renamed, rename_err = uv.fs_rename(temp_path, expected.target_path)
	if not renamed then
		remove_file(temp_path)
		return nil, "Failed to replace vault file: " .. (rename_err or "unknown error")
	end
	return true
end

local function atomic_write_ciphertext(file_path, lines, expected)
	if not lines or not lines[1] or not lines[1]:match("^%$ANSIBLE_VAULT;") then
		return nil, "Refusing to write invalid Ansible Vault ciphertext"
	end
	return atomic_replace(file_path, table.concat(lines, "\n") .. "\n", expected, "encryption")
end

Core.VaultType = { inline = "inline", file = "file" }

---Parse an ansible.cfg INI file and return vault_password_file from [defaults] if present.
---@param cfg_path string
---@return string|nil
function Core.parse_vault_password_file_from_cfg(cfg_path)
    local f = io.open(cfg_path, "r")
    if not f then
        return nil
    end
    local in_defaults = false
    for line in f:lines() do
        local section = line:match("^%[(.-)%]")
        if section then
            in_defaults = section:lower() == "defaults"
        elseif in_defaults then
            local key, value = line:match("^%s*([%w_]+)%s*=%s*(.-)%s*$")
            if key and key == "vault_password_file" and value and value ~= "" then
                f:close()
                return vim.fn.expand(value)
            end
        end
    end
    f:close()
    return nil
end

---Parse ansible-vault error output to extract available encrypt vault-ids
---@param output string
---@return string[]|nil
function Core.extract_encrypt_vault_ids(output)
	if not output or output == "" then
		return nil
	end
	-- Example: "ERROR! The vault-ids prod,default are available to encrypt. Specify the vault-id..."
	local list = output:match("[Tt]he vault%-ids%s+([^%s]+)%s+are available to encrypt")
	if not list then
		return nil
	end
	local ids = {}
	for id in list:gmatch("[^,]+") do
		local trimmed = (id:gsub("^%s+", ""):gsub("%s+$", ""))
		if trimmed ~= "" and not vim.tbl_contains(ids, trimmed) then
			table.insert(ids, trimmed)
		end
	end
	if #ids == 0 then
		return nil
	end
	return ids
end

function Core.debug(config, message)
	if config.debug then
		vim.notify("[nvim-ansible-vault] " .. message, vim.log.levels.DEBUG)
	end
end

-- Run ansible-vault with stdin. For decrypt/encrypt from stdin we direct result to stderr to avoid
-- mixing with the tool's status messages that are printed to stdout.
---@param args string[]
---@param stdin string
---@return { code: integer, stdout: string, stderr: string }
local function run_with_stdin(args, stdin, cwd, text)
	local proc = vim.system(args, { stdin = stdin, text = text ~= false, cwd = cwd })
	local res = proc:wait()
	-- Normalize fields if older signatures change
	res.stdout = res.stdout or ""
	res.stderr = res.stderr or ""
	-- Avoid logging stdin content; only sizes
	return res
end

local function get_decrypt_command(config, input, password_file)
	local cmd = { get_executable(config), "decrypt", "--output=-" }
	local resolved_password_file = password_file or config.vault_password_file
	if resolved_password_file then
		vim.list_extend(cmd, { "--vault-password-file", resolved_password_file })
	end
	table.insert(cmd, input)
	return cmd
end

---Build ansible-vault command
---@param config AnsibleVaultConfig
---@param action string
---@param file_path string
---@param opts? { encrypt_vault_id?: string }
function Core.get_vault_command(config, action, file_path, opts)
	local executable = get_executable(config)
	local cmd = { executable, action }
	if config.vault_password_file then
		table.insert(cmd, "--vault-password-file")
		table.insert(cmd, config.vault_password_file)
	end
	if opts and opts.encrypt_vault_id and action == "encrypt" then
		table.insert(cmd, "--encrypt-vault-id")
		table.insert(cmd, opts.encrypt_vault_id)
	end
	table.insert(cmd, file_path)
	Core.debug(config, string.format("cmd=%s action=%s file=%s", executable, action, file_path))
	return cmd
end

function Core.check_is_file_vault(config, file_path)
	local file = io.open(file_path, "r")
	if not file then
		return false, "Failed to open file"
	end
	local first_line = file:read("*l") -- read the first line
	file:close()
	return first_line and first_line:match("^%$ANSIBLE_VAULT;") ~= nil
end

function Core.find_inline_vault_block_at_cursor(lines, cursor_line)
	cursor_line = cursor_line or vim.api.nvim_win_get_cursor(0)[1]
	if cursor_line > #lines then
		return nil
	end

	local vault_line_num = cursor_line
	local vault_key = nil
	local line = lines[cursor_line]

	if line and line:match("^%s*[%w_-]+:%s*!vault%s*|?%-?%s*$") then
		vault_key = line:match("^%s*([%w_-]+):%s*!vault%s*|?%-?%s*$")
		vault_line_num = cursor_line
	elseif line and line:match("^%s+%S") then
		for i = cursor_line - 1, 1, -1 do
			local check_line = lines[i]
			if check_line:match("^%s*[%w_-]+:%s*!vault%s*|?%-?%s*$") then
				vault_key = check_line:match("^%s*([%w_-]+):%s*!vault%s*|?%-?%s*$")
				vault_line_num = i
				break
			elseif not check_line:match("^%s*$") and not check_line:match("^%s+") then
				break
			end
		end
	end

	if not vault_key then
		return nil
	end

	local vault_content = {}
	local vault_indent = #(lines[vault_line_num]:match("^(%s*)") or "")
	local end_line = vault_line_num

	for i = vault_line_num + 1, #lines do
		local content_line = lines[i]
		if content_line:match("^%s+%S") then
			local line_indent = #(content_line:match("^(%s*)") or "")
			if line_indent > vault_indent then
				vault_content[#vault_content + 1] = content_line
				end_line = i
			else
				break
			end
		elseif content_line:match("^%s*$") then
			end_line = i
		else
			break
		end
	end

	if #vault_content == 0 then
		return nil
	end

	return {
		key = vault_key,
		start_line = vault_line_num,
		end_line = end_line,
		vault_content = vault_content,
	}
end

---@param config AnsibleVaultConfig
---@param vault_content string[]
---@param opts? { password?: string }
---@return string|nil, string|nil
function Core.decrypt_inline_content(config, vault_content, opts)
	local stripped = {}
	for _, l in ipairs(vault_content) do
		stripped[#stripped + 1] = (l:gsub("^%s+", ""))
	end
	Core.debug(config, string.format("decrypt_inline via stdin(decrypt) lines=%d", #stripped))
	if opts and opts.password and opts.password ~= "" then
		local res, password_err = with_temporary_password_file(opts.password, function(password_file)
			return run_with_stdin(
				get_decrypt_command(config, "-", password_file),
				table.concat(stripped, "\n"),
				get_cwd(config),
				false
			)
		end)
		if not res then
			return nil, password_err
		end
		if res.code ~= 0 then
			return nil, res.stderr ~= "" and res.stderr or res.stdout or "decrypt failed"
		end
		return res.stdout
	end
	local res = run_with_stdin(
		get_decrypt_command(config, "-"),
		table.concat(stripped, "\n"),
		get_cwd(config),
		false
	)
	Core.debug(
		config,
		string.format("decrypt_inline(decrypt) exit=%d out_len=%d err_len=%d", res.code or -1, #res.stdout, #res.stderr)
	)
	if res.code ~= 0 then
		return nil, res.stderr ~= "" and res.stderr or res.stdout or "decrypt failed"
	end
	return res.stdout
end

---Encrypt text content using ansible-vault encrypt_string
---@param config AnsibleVaultConfig
---@param value string
---@param opts? { encrypt_vault_id?: string, password?: string }
function Core.encrypt_content(config, value, opts)
	Core.debug(config, string.format("encrypt_content via encrypt_string bytes=%d", #value))
	local args = { get_executable(config), "encrypt_string" }
	if config.vault_password_file and not (opts and opts.password and opts.password ~= "") then
		table.insert(args, "--vault-password-file")
		table.insert(args, config.vault_password_file)
	end
	if opts and opts.encrypt_vault_id then
		table.insert(args, "--encrypt-vault-id")
		table.insert(args, opts.encrypt_vault_id)
	end
	table.insert(args, "--stdin-name")
	table.insert(args, "value")
	local res, password_err
	if opts and opts.password and opts.password ~= "" then
		res, password_err = with_temporary_password_file(opts.password, function(password_file)
			local password_args = vim.deepcopy(args)
			if opts.encrypt_vault_id then
				vim.list_extend(password_args, { "--vault-id", opts.encrypt_vault_id .. "@" .. password_file })
			else
				vim.list_extend(password_args, { "--vault-password-file", password_file })
			end
			return run_with_stdin(password_args, value, get_cwd(config))
		end)
	else
		res = run_with_stdin(args, value, get_cwd(config))
	end
	if not res then
		return nil, password_err
	end
	Core.debug(
		config,
		string.format(
			"encrypt_content (encrypt_string) exit=%d out_len=%d err_len=%d",
			res.code or -1,
			#res.stdout,
			#res.stderr
		)
	)
	if res.code ~= 0 then
		return nil, res.stderr ~= "" and res.stderr or res.stdout or "encrypt failed"
	end
	local output = res.stdout or ""
	local out_lines = vim.split(output, "\n", { plain = true })
	if #out_lines == 0 or not out_lines[1]:match("^[^:]+:%s*!vault%s*|%-?%s*$") then
		return nil, "Unexpected output from ansible-vault encrypt_string"
	end

	local vault_lines = {}
	for i = 2, #out_lines do
		vault_lines[#vault_lines + 1] = out_lines[i]:gsub("^%s+", "")
	end
	while vault_lines[#vault_lines] == "" do
		table.remove(vault_lines)
	end
	if not vault_lines[1] or not vault_lines[1]:match("^%$ANSIBLE_VAULT;") then
		return nil, "Unexpected output from ansible-vault encrypt_string"
	end
	return vault_lines
end

---@param config AnsibleVaultConfig
---@param file_path string
---@param opts? { password?: string }
---@return string|nil, string|nil
function Core.decrypt_file_vault(config, file_path, opts)
	Core.debug(config, string.format("decrypt_file via system file=%s", file_path))
	local args
	if opts and opts.password and opts.password ~= "" then
		local res, password_err = with_temporary_password_file(opts.password, function(password_file)
			local password_args = { get_executable(config), "view", "--vault-password-file", password_file, file_path }
			return vim.system(password_args, { text = true, cwd = get_cwd(config) }):wait()
		end)
		if not res then
			return nil, password_err
		end
		if res.code ~= 0 then
			return nil, res.stderr or "Failed to view/decrypt file"
		end
		return res.stdout
	else
		args = Core.get_vault_command(config, "view", file_path)
	end
	local proc = vim.system(args, { text = true, cwd = get_cwd(config) })
	local res = proc:wait()
	Core.debug(
		config,
		string.format(
			"decrypt_file exit=%d out_len=%d err_len=%d",
			res.code or -1,
			#(res.stdout or ""),
			#(res.stderr or "")
		)
	)
	if res.code ~= 0 then
		return nil, res.stderr or "Failed to view/decrypt file"
	end
	return res.stdout
end

---@param config AnsibleVaultConfig
---@param file_path string
---@param opts? { password?: string }
---@return string|nil, string|nil
function Core.decrypt_file_content(config, file_path, opts)
	Core.debug(config, string.format("decrypt_file_content file=%s", file_path))
	local function decrypt(password_file)
		return vim.system(get_decrypt_command(config, file_path, password_file), {
			cwd = get_cwd(config),
			text = false,
		}):wait()
	end

	local res, password_err
	if opts and opts.password and opts.password ~= "" then
		res, password_err = with_temporary_password_file(opts.password, decrypt)
	else
		res = decrypt()
	end
	if not res then
		return nil, password_err
	end
	if res.code ~= 0 then
		local stderr = res.stderr or ""
		local stdout = res.stdout or ""
		return nil, stderr ~= "" and stderr or stdout ~= "" and stdout or "decrypt failed"
	end
	return res.stdout or ""
end

---Encrypt a file by first encrypting provided plaintext and writing it to file
---@param config AnsibleVaultConfig
---@param file_path string
---@param plaintext string
---@param opts? { encrypt_vault_id?: string, password?: string }
function Core.encrypt_file_with_content(config, file_path, plaintext, opts)
	Core.debug(config, string.format("encrypt_file_with_content file=%s bytes=%d", file_path, #plaintext))
	local destination, inspect_err = inspect_destination(file_path)
	if not destination then
		return nil, inspect_err
	end
	local enc_lines, err = Core.encrypt_content(config, plaintext, opts)
	if not enc_lines then
		return nil, err
	end
	local wrote, write_err = atomic_write_ciphertext(file_path, enc_lines, destination)
	if not wrote then
		return nil, write_err
	end
	Core.debug(config, string.format("wrote encrypted file lines=%d", #enc_lines))
	return true
end

---@param config AnsibleVaultConfig
---@param file_path string
---@param opts? { password?: string }
---@param expected_fingerprint? string
function Core.decrypt_file_to_plaintext(config, file_path, opts, expected_fingerprint)
	Core.debug(config, string.format("decrypt_file_to_plaintext file=%s", file_path))
	local destination, inspect_err = inspect_destination(file_path)
	if not destination then
		return nil, inspect_err
	end
	if expected_fingerprint and destination.fingerprint ~= expected_fingerprint then
		return nil, "Vault file changed before decryption; refusing to overwrite it"
	end

	local plaintext, decrypt_err = Core.decrypt_file_content(config, file_path, opts)
	if not plaintext then
		return nil, decrypt_err
	end

	local wrote, write_err = atomic_replace(file_path, plaintext, destination, "decryption")
	if not wrote then
		return nil, write_err
	end
	return true
end

return Core
