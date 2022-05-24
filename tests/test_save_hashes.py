from sha import HashFiles


class Test:
    def test_save_hashes(self):
        check_file = HashFiles(
            "./test_small", check="", algorithm="sha256", processes=1
        )
        result = check_file.save_hashes(response="123")
        assert result == "123"
