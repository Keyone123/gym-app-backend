
# Gym App Backend

API REST para gerenciamento de aplicação de academia, desenvolvida com Django e Django REST Framework.

## Tecnologias

- Django 5.0
- Django REST Framework
- djangorestframework-simplejwt (autenticação JWT)
- SQLite (padrão)

## Instalação

```bash
# Clone o repositório
git clone <seu-repositorio>
cd gym-app-backend

# Crie um ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instale as dependências
pip install -r requirements.txt

# Execute as migrações
python manage.py migrate

# Inicie o servidor
python manage.py runserver
```

## Endpoints

### Autenticação

- `POST /api/auth/register/` - Criar novo usuário
- `POST /api/auth/login/` - Fazer login
- `GET /api/auth/me/` - Obter dados do usuário autenticado

## Estrutura do Projeto

```
gym-app-backend/
├── users/           # App de autenticação e usuários
│   ├── models.py
│   ├── views.py
│   ├── serializers.py
│   └── urls.py
├── core/            # Configurações do projeto
│   └── urls.py
└── manage.py
```

## Autenticação

A API utiliza **JWT (JSON Web Tokens)** para autenticação. Inclua o token no header:

```
Authorization: Bearer <seu-access-token>
```
