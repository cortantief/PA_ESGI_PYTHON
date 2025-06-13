import tempfile
import subprocess
import os


def lfi_checker(url: str) -> str:
    """
    Runs LFITester.py with the given URL and returns the output as a string.
    """
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
        temp_path = tmp_file.name

    try:
        # Command to execute
        command = [
            "python3", "LFITester.py",
            "-o", temp_path,
            "-u", url
        ]

        # Run the command, redirect output to the temp file
        with open(os.devnull, 'w') as devnull:
            subprocess.run(command, stdout=devnull,
                           stderr=devnull, check=False)

        # Read the output from the file
        with open(temp_path, 'r') as f:
            output = f.read()

        return output

    finally:
        # Clean up the temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)


if __name__ == "__main__":
    print(lfi_checker("http://172.16.47.198/projects.php?project=i"))
