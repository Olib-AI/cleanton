# Virtual Python Environment Note

This project previously used a local Python virtual environment which was cleaned up to free disk space.

- **Virtual Environment Directory**: `.venv`
- **Python Version**: `3.12.6`
- **Removed On**: `2026-10-21 20:05:19`

### How to recreate this virtual environment:

```bash
# 1. Create a new virtual environment
python3 -m venv .venv

# 2. Activate it
source .venv/bin/activate

# 3. Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt
# or: uv pip install -r requirements.txt
```

<details>
<summary>Previously Installed Packages (pip freeze)</summary>

```text
coloredlogs==15.0.1
filelock==3.29.7
flatbuffers==25.12.19
fsspec==2026.6.0
humanfriendly==10.0
iniconfig==2.3.0
Jinja2==3.1.6
MarkupSafe==3.0.3
mpmath==1.3.0
networkx==3.6.1
numpy==2.1.3
onnx==1.18.0
onnxruntime==1.23.2
packaging==26.2
pluggy==1.6.0
protobuf==7.35.1
pytest==8.3.4
setuptools==83.0.0
sympy==1.14.0
torch==2.9.0
typing_extensions==4.16.0
```
</details>
