FROM python:3.10-slim

WORKDIR /workspace

# Install Python deps for the app
COPY app/requirements.txt /tmp/app-requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/app-requirements.txt

# Copy the whole repo, since app depends on sibling folders
COPY . /workspace

# Run from the app directory
WORKDIR /workspace/app

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]