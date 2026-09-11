.PHONY: test

test:
	nvim --headless -u tests/minimal_init.lua -c "luafile tests/run.lua"
