from sha import HashFiles


class Test:
    def test_hash_multiprocessing(self):
        check_file = HashFiles(
            "./test_small", check="", algorithm="sha256", processes=1
        )
        result = check_file.hash_multiprocessing()
        assert str(result) == "<multiprocessing.pool.Pool state=TERMINATE pool_size=16>"
