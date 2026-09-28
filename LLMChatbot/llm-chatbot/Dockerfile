# Built by .github/workflows/devsecops-app.yml. Pin the base by digest once you have scanned it:
#   docker buildx imagetools inspect python:3.12-slim   → FROM python:3.12-slim@sha256:<digest>
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY llm-chatbot.py .
USER 10001
HEALTHCHECK CMD python -c "import transformers" || exit 1
ENTRYPOINT ["python", "llm-chatbot.py"]
