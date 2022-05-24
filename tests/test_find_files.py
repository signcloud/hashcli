from sha import HashFiles


class Test:
    def test_find_files(self):
        check_file = HashFiles(
            "./test_small", check="", algorithm="sha256", processes=1
        )
        result = check_file.find_files()
        assert isinstance(result, list)
