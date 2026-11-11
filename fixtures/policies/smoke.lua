return {
	name = "smoke",
	author = "Lua-LSM testsuite",
	description = "Always allow file_permission",
	license = "GPL-2.0",
	version = 1,

	file_permission = function(file, mask)
		return true
	end,
}
