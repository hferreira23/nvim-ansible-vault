# nvim-ansible-vault

A Neovim plugin for viewing, editing, encrypting, and decrypting Ansible Vault
content. It supports both whole-file vaults and inline YAML `!vault` values.

> [!IMPORTANT]
> This is a personal-use fork with no guarantee of support or stability. Most
> of the code in this fork is AI-written or AI-rewritten, then reviewed and
> tested by the maintainer. Review the implementation and test it against your
> own workflow before trusting it with important secrets.

## Credits and provenance

This repository is forked from
[`19bischof/nvim-ansible-vault`](https://github.com/19bischof/nvim-ansible-vault).
The original plugin, concept, and initial implementation are the work of
[`@19bischof`](https://github.com/19bischof), who deserves full credit for the
project this fork builds on.

The fork adds substantial AI-assisted changes around write safety, conflict
detection, password handling, popup lifecycle management, permanent
decryption, and regression testing. The original MIT license is retained.

## Features

- Open whole-file and inline vaults in an editable plaintext popup.
- Re-encrypt edited popup content without first writing plaintext to disk.
- Encrypt the current buffer as a whole-file vault, including unsaved edits.
- Encrypt a simple YAML scalar as an inline `!vault` block.
- Permanently decrypt whole-file or inline vaults after explicit confirmation.
- Discover the nearest project Ansible configuration automatically.
- Work with `vault_password_file` and multiple `vault_identity_list` entries.
- Prompt for a one-time password when Ansible cannot resolve a vault secret.
- Detect source-buffer and on-disk changes before replacing vault content.
- Atomically replace whole-file vaults while preserving standard Unix `rwx`
  permission bits and ownership.
- Reject unsafe whole-file replacements involving hard links.

## Requirements

### Neovim

- Neovim 0.10 or newer.
- `git` when installing through a plugin manager or cloning manually.
- A clipboard provider is optional and only needed for the popup `y` mapping.
- `make` is optional and only needed to run the test suite.

The plugin uses built-in APIs such as `vim.system`, `vim.fs`, `vim.ui.select`,
and `vim.json`. It has no Lua plugin dependencies.

### Ansible

- `ansible-vault` from Ansible Core, available on `$PATH` or configured through
  `vault_executable`.
- A modern Ansible Core release with `encrypt_string`, `view`, and
  `decrypt --output=-`. Ansible Core 2.12 or newer is recommended.
- A vault password source configured through `ansible.cfg`, an explicit
  password file, or the plugin's one-time password prompt.

The current implementation and smoke tests use Ansible Core 2.16.14. Verify
your installation with:

```sh
ansible-vault --version
```

Common installation options include:

```sh
pipx install ansible-core
```

or, on macOS with Homebrew:

```sh
brew install ansible
```

## Installation

### lazy.nvim

Add this specification to your regular Neovim lazy.nvim setup:

```lua
{
  "hferreira23/nvim-ansible-vault",
  opts = {},
}
```

`opts = {}` calls `require("ansible-vault").setup({})` and uses automatic
`ansible.cfg` discovery, the `ansible-vault` executable on `$PATH`, and the
default mappings.

### LazyVim

Create `~/.config/nvim/lua/plugins/ansible-vault.lua`:

```lua
return {
  {
    "hferreira23/nvim-ansible-vault",
    cmd = {
      "AnsibleVaultAccess",
      "AnsibleVaultEncryptFile",
      "AnsibleVaultEncryptInline",
      "AnsibleVaultDecryptFile",
      "AnsibleVaultDecryptInline",
    },
    keys = {
      { "<leader>va", "<cmd>AnsibleVaultAccess<cr>", desc = "Ansible Vault Access" },
      { "<leader>vE", "<cmd>AnsibleVaultEncryptFile<cr>", desc = "Ansible Vault Encrypt File" },
      { "<leader>ve", "<cmd>AnsibleVaultEncryptInline<cr>", desc = "Ansible Vault Encrypt Inline" },
      { "<leader>vD", "<cmd>AnsibleVaultDecryptFile<cr>", desc = "Ansible Vault Decrypt File" },
      { "<leader>vd", "<cmd>AnsibleVaultDecryptInline<cr>", desc = "Ansible Vault Decrypt Inline" },
    },
    init = function()
      vim.g.ansible_vault_no_default_mappings = 1
    end,
    opts = {},
  },
}
```

The `init` setting prevents the plugin's default mappings from duplicating the
lazy-loaded mappings declared by LazyVim.

### Native packages

For Neovim's built-in package loading, clone the repository into a `start`
package:

```sh
git clone https://github.com/hferreira23/nvim-ansible-vault.git \
  ~/.local/share/nvim/site/pack/ansible/start/nvim-ansible-vault
```

Then configure it in `init.lua`:

```lua
require("ansible-vault").setup({})
```

## Configuration

The defaults are equivalent to:

```lua
require("ansible-vault").setup({
  ansible_cfg_directory = nil,
  vault_password_file = nil,
  vault_executable = "ansible-vault",
  debug = false,
})
```

| Option | Default | Description |
| --- | --- | --- |
| `ansible_cfg_directory` | `nil` | Directory in which Ansible commands run. When omitted, the plugin searches upward from the current file for project configuration. |
| `vault_password_file` | `nil` | Explicit password file passed to `ansible-vault`. Usually unnecessary when `ansible.cfg` already defines vault identities. |
| `vault_executable` | `"ansible-vault"` | Executable name or absolute path to `ansible-vault`. |
| `debug` | `false` | Emit debug notifications containing command metadata and content lengths, but not plaintext or passwords. |

Example with an explicit executable and project directory:

```lua
require("ansible-vault").setup({
  ansible_cfg_directory = vim.fn.expand("~/src/infrastructure"),
  vault_executable = "/opt/homebrew/bin/ansible-vault",
  debug = false,
})
```

### Ansible configuration

When `ansible_cfg_directory` is omitted, the plugin searches upward from the
current file for `ansible.cfg` or `.ansible.cfg` and runs Ansible in that
directory. A project `ansible.cfg` is loaded normally by Ansible, including
settings such as `vault_identity_list`.

For compatibility with the original plugin, auto-discovery can also read
`vault_password_file` from a project `.ansible.cfg`. Ansible does not treat a
project `.ansible.cfg` as its full configuration, so other settings in that
file, including `vault_identity_list`, do not take effect. Prefer a project
`ansible.cfg` for complete and predictable behavior. An explicit
`ansible_cfg_directory` also expects `ansible.cfg` in that directory.

Example `ansible.cfg` for multiple vault identities:

```ini
[defaults]
vault_identity_list = default@~/.ansible/.vault_pass.txt,prod@~/.ansible/.vault_pass_prod.txt
```

Example for one password file:

```ini
[defaults]
vault_password_file = ~/.ansible/.vault_pass.txt
```

Do not commit password files. Restrict their permissions, for example:

```sh
chmod 600 ~/.ansible/.vault_pass.txt
```

Review a project's Ansible configuration before invoking this plugin in an
untrusted checkout. Ansible vault password sources can be executable scripts,
and the plugin runs `ansible-vault` using the discovered project context.

If no configured identity can decrypt the content, the plugin prompts for a
one-time password. That password is passed to Ansible through a temporary
mode-0600 file and is not stored in the plugin configuration.

## Usage

### Default shortcuts

| Shortcut | Action |
| --- | --- |
| `<leader>va` | Access the whole-file vault or inline vault at the cursor in a secure popup. |
| `<leader>vE` | Encrypt the entire current buffer as a whole-file vault. |
| `<leader>ve` | Encrypt the simple YAML scalar at the cursor as an inline vault. |
| `<leader>vD` | Permanently decrypt a whole-file vault to plaintext on disk. |
| `<leader>vd` | Permanently decrypt the inline vault at the cursor into the current buffer. |

The default leader is controlled by your Neovim configuration. For example,
if `vim.g.mapleader = " "`, `<leader>va` means `Space`, `v`, `a`.

### Commands

| Command | Action |
| --- | --- |
| `:AnsibleVaultAccess` | Open the whole-file vault or inline vault at the cursor. |
| `:AnsibleVaultEncryptFile` | Encrypt the current buffer as a whole-file vault. |
| `:AnsibleVaultEncryptInline` | Encrypt the simple YAML scalar at the cursor. |
| `:AnsibleVaultDecryptFile` | Permanently decrypt a whole-file vault. |
| `:AnsibleVaultDecryptInline` | Permanently decrypt the inline vault at the cursor. |

### Popup controls

| Shortcut | Modes | Action |
| --- | --- | --- |
| `<C-s>` | Normal, insert | Re-encrypt changes and close the popup. |
| `<CR>` | Normal | Re-encrypt changes and close the popup. |
| `<Esc>` or `q` | Normal | Close without applying changes. |
| `y` | Normal | Copy all popup plaintext to the `+` clipboard register. |
| `?` | Normal | Show popup help. |

### Edit and re-encrypt

For an inline value, place the cursor on either the `!vault` header or one of
its encrypted lines. For a whole-file vault, the cursor may be anywhere in the
file. Run `:AnsibleVaultAccess` or press `<leader>va`.

The plugin decrypts the content into a `nofile` buffer with swap disabled. Edit
the plaintext and press `<C-s>` or `<CR>` to re-encrypt it. From normal mode,
closing with `<Esc>` or `q` discards popup changes. In insert mode, use
`<C-s>` to save directly or press `<Esc>` once to return to normal mode.

Inline edits update the source buffer, which you must save normally. Whole-file
edits are encrypted and atomically written to the source file before its buffer
is reloaded.

### Encrypt a whole file

Open a plaintext file and run `:AnsibleVaultEncryptFile` or press
`<leader>vE`. The command encrypts the current buffer contents, including
unsaved edits, without first saving plaintext to disk.

If Ansible reports multiple eligible vault IDs, the plugin opens a
`vim.ui.select` prompt. If it cannot find a password, it requests a one-time
password.

### Encrypt an inline value

Place the cursor on a simple, non-empty YAML scalar:

```yaml
database_password: correct-horse-battery-staple
```

Run `:AnsibleVaultEncryptInline` or press `<leader>ve`. The line becomes an
inline vault block in the current buffer. Save the buffer to persist it.

Inline encryption currently targets unquoted, comment-free `key: value` lines
whose keys use letters, digits, underscores, or hyphens. It encrypts the raw
text after the colon rather than parsing YAML, so quote characters and inline
comments would become part of the secret. It is not a general YAML parser.

### Permanently decrypt content

`<leader>vD` permanently replaces a whole-file vault with plaintext on disk.
The source buffer must be unmodified and still match the file on disk.

`<leader>vd` replaces the inline vault at the cursor with a quoted YAML scalar
in the current buffer. Save the buffer to persist the plaintext.

Both operations show an explicit confirmation prompt. `Cancel` is the first
choice. Permanent decryption is intentionally separate from popup access
because it can expose secrets to editors, backups, file indexers, version
control, and other local processes.

## Custom shortcuts

Disable defaults before the plugin loads and define your own mappings:

```lua
vim.g.ansible_vault_no_default_mappings = 1

vim.keymap.set("n", "<leader>va", "<Cmd>AnsibleVaultAccess<CR>", { desc = "Vault access" })
vim.keymap.set("n", "<leader>vE", "<Cmd>AnsibleVaultEncryptFile<CR>", { desc = "Vault encrypt file" })
vim.keymap.set("n", "<leader>ve", "<Cmd>AnsibleVaultEncryptInline<CR>", { desc = "Vault encrypt inline" })
vim.keymap.set("n", "<leader>vD", "<Cmd>AnsibleVaultDecryptFile<CR>", { desc = "Vault decrypt file" })
vim.keymap.set("n", "<leader>vd", "<Cmd>AnsibleVaultDecryptInline<CR>", { desc = "Vault decrypt inline" })
```

## Safety model

- Popup plaintext lives in an unlisted `nofile` buffer with swap disabled.
- Whole-file encryption uses current buffer contents and does not save
  plaintext first.
- Whole-file writes use a mode-0600 temporary file in the destination
  directory, validate the destination, apply the original Unix `rwx`
  permission bits and owner/group, and atomically rename the result.
- Symlink paths retain the symlink and replace its resolved target.
- Whole-file writes reject non-regular files and files with multiple hard
  links.
- Buffer changed-ticks and file fingerprints prevent known stale or concurrent
  updates from being overwritten.
- One-time passwords use temporary mode-0600 files that are removed after the
  Ansible process finishes.
- Inline permanent decryption safely quotes the result as a YAML scalar.
- Copying popup content with `y` deliberately places plaintext in the system
  clipboard.

These protections reduce accidental plaintext writes and lost updates; they do
not make Neovim a secret-isolation boundary. Atomic replacement preserves the
standard `0777` permission bits and owner/group, but not special setuid, setgid,
or sticky bits, and it does not guarantee preservation of every filesystem ACL
or extended attribute. Keep backups, review diffs carefully, and avoid running
permanent decryption inside a repository unless that is intentional.

## Troubleshooting

### `ansible-vault` is not executable

Confirm the command is available:

```sh
command -v ansible-vault
ansible-vault --version
```

If it is installed outside `$PATH`, set `vault_executable` to its absolute
path.

### No vault secrets were found

Check that Neovim opened a file beneath the intended `ansible.cfg`, or set
`ansible_cfg_directory` explicitly. Also verify paths in `vault_identity_list`
or `vault_password_file` outside Neovim.

### Encryption asks for a vault ID

This is expected when Ansible knows several identities but no default
encryption identity. Select the intended identity in the prompt or configure a
default in `ansible.cfg`.

### A write is cancelled because the source changed

The plugin detected a changed buffer or destination file and refused to
overwrite it. Reopen or reload the source, reconcile the changes, and retry.

## Testing

The repository includes a headless Neovim regression suite. From the repository
root, run:

```sh
make test
```

This executes:

```sh
nvim --headless -u tests/minimal_init.lua -c "luafile tests/run.lua"
```

The suite stubs external process results where appropriate and covers atomic
writes, permissions, ownership, links, password-file cleanup, stale-source
protection, popup lifecycle behavior, permanent decryption, exact plaintext
output, and YAML scalar encoding.

For changes to Ansible CLI integration, also perform a real round trip with the
Ansible Core version you support. Never use production secrets as test data.

## Support and license

This fork exists for the maintainer's own workflow. Issues and pull requests
may be reviewed, but support, compatibility, and release schedules are not
guaranteed.

Licensed under the [MIT License](LICENSE).
