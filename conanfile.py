#!/usr/bin/env python
# -*- coding: utf-8 -*-

from conans import ConanFile, CMake, tools
import os

class Libssh2Conan(ConanFile):
    name = "libssh2"
    version = "1.9.0_mod2"
    description = "SSH2 modified library"
    url = "https://github.com/bincrafters/conan-libssh2"
    homepage = "https://libssh2.org"
    license = "BSD 3-Clause"
    exports = ["LICENSE.md"]
    exports_sources = ["CMakeLists.txt"]
    generators = "cmake"
    source_subfolder = "source_subfolder"
    install_subfolder = "install_subfolder"

    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "with_zlib": [True, False],
        "enable_crypt_none": [True, False],
        "enable_mac_none": [True, False],
        "with_openssl": [True, False]
    }

    default_options = {
        "shared": False,
        "fPIC": True,
        "with_zlib": True,
        "enable_crypt_none": False,
        "enable_mac_none": False,
        "with_openssl": True
    }

    def source(self):
        if True: # if running from own customized version (needed due to exports renaming)
            git=tools.Git(folder="libssh2")
            git.clone("https://github.com/pietermessely/libssh2.git")
        else:
            git=tools.Git(folder="libssh2")
            git.clone("https://github.com/sahlberg/libnfs.git")
        os.rename("libssh2", self.source_subfolder)


    def configure(self):
        del self.settings.compiler.libcxx

    def requirements(self):
        if self.options.with_zlib:
            self.requires.add("zlib/1.2.11")
        if self.options.with_openssl:
            #self.requires.add("OpenSSL/latest_1.0.2x@conan/stable")
            #self.requires.add("openssl/1.1.1h")
            self.requires.add("openssl/1.1.1k") #Had to install this first: conan install openssl/1.1.1k@ or simply add --build missing when calling this ...


    def build(self):
        cmake = CMake(self)

        cmake.definitions['BUILD_SHARED_LIBS'] = self.options.shared
        cmake.definitions['ENABLE_ZLIB_COMPRESSION'] = self.options.with_zlib
        cmake.definitions['ENABLE_CRYPT_NONE'] = self.options.enable_crypt_none
        cmake.definitions['ENABLE_MAC_NONE'] = self.options.enable_mac_none
        if self.options.with_openssl:
            cmake.definitions['CRYPTO_BACKEND'] = 'OpenSSL'
            #cmake.definitions['OPENSSL_ROOT_DIR'] = self.deps_cpp_info['OpenSSL'].rootpath
            cmake.definitions['OPENSSL_ADDITIONAL_LIBRARIES'] = 'dl'
        else:
            raise Exception("Crypto backend must be specified")
        cmake.definitions['BUILD_EXAMPLES'] = False
        cmake.definitions['BUILD_TESTING'] = False
        cmake.definitions['CMAKE_INSTALL_PREFIX'] = self.install_subfolder

        cmake.configure()
        cmake.build()
        cmake.install()


    def package(self):
        self.copy("COPYING", dst="licenses", src=self.source_subfolder, keep_path=False)
        self.copy("*", dst="include", src=os.path.join(self.install_subfolder, "include"))
        self.copy("libssh2_config.h", dst="include", src=os.path.join(self.source_subfolder, "src"))
        self.copy("*.dll", dst="bin", src=os.path.join(self.install_subfolder, "bin"), keep_path=False)
        self.copy("*.dylib", dst="lib", src=os.path.join(self.install_subfolder, "lib"), keep_path=False)
        # rhel installs libraries into lib64
        # cannot use cmake install into package_folder because of lib64 issue
        for libarch in ['lib', 'lib64']:
            arch_dir = os.path.join(self.install_subfolder, libarch)
            cmake_dir_src = os.path.join(arch_dir, "cmake", "libssh2")
            cmake_dir_dst = os.path.join("lib", "cmake", "libssh2")
            pkgconfig_dir_src = os.path.join(arch_dir, "pkgconfig")
            pkgconfig_dir_dst = os.path.join("lib", "pkgconfig")

            self.copy("*.lib", dst="lib", src=arch_dir, keep_path=False)
            self.copy("*.a", dst="lib", src=arch_dir, keep_path=False)
            self.copy("*.so*", dst="lib", src=arch_dir, keep_path=False)
            self.copy("*.*", dst=cmake_dir_dst, src=cmake_dir_src)
            self.copy("*.*", dst=pkgconfig_dir_dst, src=pkgconfig_dir_src)

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)

        if self.settings.compiler == "Visual Studio":
            if not self.options.shared:
                self.cpp_info.libs.append('ws2_32')
        elif self.settings.os == "Linux":
            # Needed to build bundled examples with openssl
            self.cpp_info.libs.append('dl')

