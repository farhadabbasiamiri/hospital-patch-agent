# Local, reproducible run (no cloud). Ollama runs on the host machine.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python scripts/generate_data.py
ENV OLLAMA_URL=http://host.docker.internal:11434 \
    OLLAMA_MODEL=qwen2.5:7b \
    GRADIO_ANALYTICS_ENABLED=False
EXPOSE 7860
CMD ["python", "-m", "app.ui"]
