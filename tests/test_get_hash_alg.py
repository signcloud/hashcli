from sha import HashFiles

dictionary = dict()
with open("check_hashes", "r") as file:
    for line in file:
        elements = line.split()
        dictionary[elements[0]] = elements[1] + "  " + elements[2]

# file = None
check = ""
algorithm = "sha256"


class Test:
    @classmethod
    def setup_class(cls):
        test_file = open("test_file", "w")
        test_file.close()

    @classmethod
    def teardown_class(cls):
        pass

    def test_get_hash_alg_md5(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="md5", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["md5"]
        )

    def test_get_hash_alg_sha512(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha512", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha512"]
        )

    def test_get_hash_alg_sha384(self):
        assert (
            str(
                HashFiles(
                    "test_file", check, algorithm="sha384", processes=1
                ).get_hash_algorithm("test_file")
            )
            == dictionary["sha384"]
        )

    def test_get_hash_alg(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha256", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha256"]
        )

    def test_get_hash_alg_blake2s(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="blake2s", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["blake2s"]
        )

    def test_get_hash_alg_sha3_512(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha3_512", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha3_512"]
        )

    def test_get_hash_alg_sha3_384(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha3_384", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha3_384"]
        )

    def test_get_hash_alg_shake_256(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="shake_256", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["shake_256"]
        )

    def test_get_hash_alg_sha224(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha224", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha224"]
        )

    def test_get_hash_alg_shake_128(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="shake_128", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["shake_128"]
        )

    def test_get_hash_alg_sha3_224(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha3_224", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha3_224"]
        )

    def test_get_hash_alg_sha1(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha1", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha1"]
        )

    def test_get_hash_alg_blake2b(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="blake2b", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["blake2b"]
        )

    def test_get_hash_alg_sha3_256(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha3_256", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha3_256"]
        )

    def test_get_hash_alg_sha512_224(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha512_224", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha512_224"]
        )

    def test_get_hash_alg_whirlpool(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="whirlpool", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["whirlpool"]
        )

    def test_get_hash_alg_ripemd160(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="ripemd160", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["ripemd160"]
        )

    def test_get_hash_alg_sha512_256(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sha512_256", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sha512_256"]
        )

    def test_get_hash_alg_md4(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="md4", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["md4"]
        )

    def test_get_hash_alg_sm3(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="sm3", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["sm3"]
        )

    def test_get_hash_alg_md5_sha1(self):
        assert (
            HashFiles(
                "test_file", check, algorithm="md5-sha1", processes=1
            ).get_hash_algorithm("test_file")
            == dictionary["md5-sha1"]
        )
