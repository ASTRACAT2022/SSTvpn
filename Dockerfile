FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Копирование requirements и установка зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование кода приложения
COPY . .

# Создание директории для instance (база данных и кэш)
RUN mkdir -p instance/cache

# Открытие порта
EXPOSE 5000

# Команда запуска
CMD ["gunicorn", "--workers", "3", "--bind", "0.0.0.0:5000", "--timeout", "120", "app:app"]

