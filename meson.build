project(
	'dareog',
	'c',
	version: '0.0.0',
	license: 'MIT',
	meson_version: '>=0.43.0',
	default_options: [
		'c_std=c11',
		'warning_level=2',
		'werror=true',
	],
)

add_project_arguments('-Wno-unused-parameter', language: 'c')

dareog_inc = include_directories('include')

arch = target_machine.cpu_family().split('_')[0]
arch_inc = include_directories('arch/'+arch+'/include')

dwarfw = dependency('dwarfw', fallback: ['libdwarfw', 'dwarfw'])
elf = dependency('libelf')

executable(
	'dareog',
	files([
		'dareog.c',
		'dump.c',
		'generate-dwarf.c',
		'symbols.c',
	]),
	dependencies: [dwarfw, elf],
	include_directories: [dareog_inc, arch_inc],
	install: true,
)
