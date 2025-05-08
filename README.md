# 🧹 Strippy - PE Cleaner

**Strippy** is a command-line tool for cleaning Portable Executable (PE) files by removing debug information, relocation sections, padding, resource data, and overlay content. It is designed to help reduce file size, sanitize binaries, and prepare executables for analysis or distribution.

---

## 🚀 Features

- **Debug Stripping**: Removes debug directory entries from the PE header.  
- **Relocation Cleanup**: Removes relocation sections (32-bit only).  
- **IAT Clearing**: Clears the Import Address Table directory entry.  
- **.rdata Padding Trimming**: Reduces raw size of read-only data sections.  
- **Resource Section Removal**: Deletes embedded resources from the binary.  
- **Overlay Truncation**: Removes data appended to the end of the file.  
- **.NET Detection**: Skips unsafe operations on .NET assemblies.  
- **All-in-One Option**: Applies all available modifications with a single flag, excluding resource stripping.

---

## 🛠️ How It Works

1. **Select Input & Output Files**  
   - Provide the path to a valid PE file and specify where to save the modified result using `-o`.

2. **Choose Modifications**  
   - Use one or more flags (e.g. `-d`, `-l`, `-I`, `-O`, `-R`, `-r`, or `-a`) to define what gets stripped.

3. **Run Strippy**  
   - The tool loads the PE file, applies modifications, and writes the cleaned version to disk.

4. **Optional: Use `--all`**  
   - Use `-a` or `--all` to apply all stripping operations automatically.

---

## 💻 Example Usage

```bash
# Remove debug and relocation sections
python strippy.py input.exe -d -l -o cleaned.exe

# Apply all stripping options
python strippy.py input.exe -a -o stripped.exe
```
---

## ❗ Requirements

Install dependencies with:

```bash
pip install pefile
```
## 📜 License

This project is released under the [MIT License](LICENSE).
