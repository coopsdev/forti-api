from conan import ConanFile
from conan.tools.meson import Meson
from conan.tools.files import copy


class Pkg(ConanFile):
    name = "forti_api"
    version = "0.1.0"
    author = "Cooper Larson | cooper.larson1@gmail.com"
    url = ""
    description = "FortiGate API interface"
    topics = ("c++", "security", "DNS blocklists", "fail2ban")
    settings = "os", "compiler", "arch", "build_type"
    requires = [
        'nlohmann_json/3.11.3',
        'json-schema-validator/2.3.0',
        'libcurl/8.9.1'
    ]
    generators = "PkgConfigDeps", "MesonToolchain"
    exports_sources = "meson.build", "include/*", "main.cpp"
    implements = ["auto_header_only"]

    def layout(self):
        self.folders.source = '.'
        self.folders.build = 'build/meson'
        self.folders.generators = 'build/generators'
        self.folders.package = 'build/package'

    def build(self):
        meson = Meson(self)
        meson.configure()
        meson.build()

    def test(self):
        meson = Meson(self)
        meson.test()

    def package(self):
        copy(self, "*.hpp", self.source_folder, self.package_folder)

    def package_info(self):
        self.cpp_info.includedirs = ['include']
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []

    def package_id(self):
        self.info.clear()
