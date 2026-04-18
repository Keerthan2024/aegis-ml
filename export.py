import os

repo_dir = r"c:\Users\Admin\aegis"
output_file = os.path.join(repo_dir, "aegis_full_project.md")
include_exts = {".py", ".jsx", ".js", ".css", ".md"}
exclude_dirs = {"node_modules", ".git", ".venv", "__pycache__", "datasets", "dist", "build", "public", ".gemini", "tmp", "brain"}

with open(output_file, 'w', encoding='utf-8') as out:
    out.write("# AEGIS Complete Project Source\n\n")
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            if any(file.endswith(ext) for ext in include_exts) and file not in {"aegis_full_project.md", "README.md", "export.py"}:
                path = os.path.join(root, file)
                rel_path = os.path.relpath(path, repo_dir)
                out.write(f"## File: {rel_path}\n```\n")
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    out.write(f.read())
                out.write("\n```\n\n")

print(f"Exported to {output_file}")
