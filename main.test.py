from main import extract_file_info

def test_extract_file_info_with_empty_dict():
    # Test case: Should return tuple of (None, None) when input is an empty dictionary
    result = extract_file_info({})
    assert result == (None, None), f"Expected (None, None), but got {result}"

def test_extract_file_info_with_object():
    # Test case: Should return correct file name and content when input is an object with 'name' and 'content' attributes
    class FileObject:
        def __init__(self, name, content):
            self.name = name
            self.content = content

    file_obj = FileObject("test_file.txt", b"file content")
    result = extract_file_info(file_obj)
    assert result == ("test_file.txt", b"file content"), f"Expected ('test_file.txt', b'file content'), but got {result}"
