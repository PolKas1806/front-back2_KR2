# Практические задания 7-9 — Auth + Products API

## Установка и запуск

```bash
npm install
npm start
```

Сервер запустится на `http://localhost:3000`  
Swagger UI доступен по адресу `http://localhost:3000/api-docs`

---

## Маршруты API

### Auth

| Метод | Маршрут              | Защита | Описание                              |
|-------|----------------------|--------|---------------------------------------|
| POST  | /api/auth/register   | —      | Регистрация пользователя              |
| POST  | /api/auth/login      | —      | Вход в систему, возвращает пару токенов |
| POST  | /api/auth/refresh    | —      | Обновить пару access + refresh токенов |
| GET   | /api/auth/me         | 🔒 JWT | Получить текущего пользователя        |

### Products

| Метод  | Маршрут           | Защита | Описание                  |
|--------|-------------------|--------|---------------------------|
| POST   | /api/products     | —      | Создать товар             |
| GET    | /api/products     | —      | Получить список товаров   |
| GET    | /api/products/:id | 🔒 JWT | Получить товар по id      |
| PUT    | /api/products/:id | 🔒 JWT | Обновить параметры товара |
| DELETE | /api/products/:id | 🔒 JWT | Удалить товар             |

---

## Аутентификация (JWT)

После входа через `/api/auth/login` сервер возвращает два токена — `accessToken` и `refreshToken`.  
Для защищённых маршрутов необходимо передавать access-токен в заголовке:

```
Authorization: Bearer <accessToken>
```

- **accessToken** — действителен **15 минут**
- **refreshToken** — действителен **7 дней**

Когда access-токен истекает, отправь refresh-токен на `/api/auth/refresh` — сервер выдаст новую пару токенов. Старый refresh-токен при этом становится недействительным (ротация).

---

## Примеры запросов

### Регистрация
```json
POST /api/auth/register
{
  "email": "ivan@example.com",
  "first_name": "Иван",
  "last_name": "Иванов",
  "password": "secret123"
}
```

### Вход
```json
POST /api/auth/login
{
  "email": "ivan@example.com",
  "password": "secret123"
}
```
Ответ:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Обновить токены
```json
POST /api/auth/refresh
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
Ответ:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Получить текущего пользователя
```
GET /api/auth/me
Authorization: Bearer <accessToken>
```

### Создать товар
```json
POST /api/products
{
  "title": "Телевизор",
  "category": "Электроника",
  "description": "LG Oled",
  "price": 130000
}
```

### Получить товар по id (требует токен)
```
GET /api/products/<id>
Authorization: Bearer <accessToken>
```

---

## Сущности

### Пользователь
| Поле           | Тип    | Описание              |
|----------------|--------|-----------------------|
| id             | string | UUID (генерируется)   |
| email          | string | Логин пользователя    |
| first_name     | string | Имя                   |
| last_name      | string | Фамилия               |
| hashedPassword | string | bcrypt-хеш пароля     |

### Товар
| Поле        | Тип    | Описание            |
|-------------|--------|---------------------|
| id          | string | UUID (генерируется) |
| title       | string | Название            |
| category    | string | Категория           |
| description | string | Описание            |
| price       | number | Цена                |