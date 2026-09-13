FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DEFAULT_TIMEOUT=300 \
    PIP_RETRIES=10

WORKDIR /app

# Установка зависимостей с увеличенным таймаутом и повторными попытками
COPY server/requirements.txt /app/server/requirements.txt
RUN pip install --default-timeout=300 --retries 10 -r server/requirements.txt

# Копирование исходного кода сервера и клиента
COPY server/ /app/server/
COPY client/ /app/client/

EXPOSE 8888

CMD ["python", "-m", "server.main"]
