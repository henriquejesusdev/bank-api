# API Bancária Assíncrona

Uma API RESTful assíncrona desenvolvida com FastAPI para gerenciamento de contas correntes, transações bancárias (depósitos e saques) e autenticação de usuários com JWT. O projeto utiliza SQLAlchemy para persistência de dados em um banco SQLite e Poetry para gerenciamento de dependências.

## Índice

- [Descrição](#descrição)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Execução](#execução)
- [Uso](#uso)
- [Endpoints](#endpoints)
- [Licença](#licença)
- [Contato](#contato)

## Descrição

A API Bancária Assíncrona é uma aplicação web que permite a criação e autenticação de usuários, gerenciamento de contas correntes e realização de transações financeiras (depósitos e saques). A autenticação é baseada em tokens JWT, garantindo segurança para operações protegidas. O projeto utiliza um banco de dados SQLite para desenvolvimento, com suporte a migrações para outros bancos (como PostgreSQL) em produção. A documentação interativa é gerada automaticamente pelo FastAPI e está disponível em `/docs`.

### Funcionalidades
- **Gerenciamento de Usuários**: Criação de novos usuários com nome de usuário e senha criptografada (usando bcrypt).
- **Autenticação**: Login com geração de tokens JWT para acesso seguro aos endpoints.
- **Gerenciamento de Contas**: Criação automática de uma conta corrente associada a cada usuário.
- **Transações**: Suporte a depósitos e saques, com validação de saldo para saques.
- **Consulta de Extrato**: Recuperação de detalhes da conta, incluindo saldo e histórico de transações.

### Tecnologias Utilizadas
- **FastAPI**: Framework web assíncrono para construção da API.
- **SQLAlchemy**: ORM para gerenciamento do banco de dados.
- **SQLite**: Banco de dados leve para desenvolvimento.
- **Pydantic**: Validação de dados e definição de esquemas.
- **python-jose**: Geração e validação de tokens JWT.
- **passlib**: Criptografia de senhas com bcrypt.
- **python-multipart**: Suporte a dados de formulário para autenticação.
- **Poetry**: Gerenciamento de dependências e ambiente virtual.

### Arquitetura
A API segue uma arquitetura RESTful com uma abordagem modular. O código principal está em `src/bank_api/main.py`, que define:
- Modelos do banco de dados (SQLAlchemy) para usuários, contas e transações.
- Modelos Pydantic para validação de entrada e saída de dados.
- Endpoints protegidos por autenticação JWT.
- Dependências para gerenciamento de sessões do banco de dados.

O projeto é configurado para ser facilmente escalável, com suporte a bancos de dados mais robustos (como PostgreSQL) e ferramentas de migração como Alembic.

## Pré-requisitos

- **Python 3.13+**: Versão mínima necessária.
- **Poetry**: Ferramenta de gerenciamento de dependências e ambientes virtuais.
- **Git**: Para clonar o repositório (opcional).

## Instalação

1. **Clone o repositório** (se aplicável):
   ```bash
   git clone <url-do-repositorio>
   cd bank-api
   ```

2. **Instale o Poetry** (se ainda não estiver instalado):
   ```bash
   pip install poetry
   ```

3. **Instale as dependências do projeto**:
   Na pasta raiz do projeto (`bank-api`), execute:
   ```bash
   poetry install
   ```

   Isso cria um ambiente virtual e instala todas as dependências listadas no `pyproject.toml`.

4. **Ative o ambiente virtual** (opcional, se quiser trabalhar diretamente no shell):
   ```bash
   poetry shell
   ```

## Execução

1. **Inicie o servidor**:
   Na pasta raiz do projeto, execute:
   ```bash
   poetry run uvicorn bank_api.main:app --reload
   ```

   - `--reload`: Habilita o modo de recarga automática para desenvolvimento.
   - O servidor estará disponível em `http://127.0.0.1:8000`.

2. **Acesse a documentação interativa**:
   - Abra `http://127.0.0.1:8000/docs` para a interface Swagger.
   - Ou acesse `http://127.0.0.1:8000/redoc` para a interface Redoc.

## Uso

### Endpoints

A API oferece os seguintes endpoints, todos documentados na interface Swagger (`/docs`):

1. **POST /users/**:
   - **Descrição**: Cria um novo usuário e uma conta associada, retornando um token JWT.
   - **Exemplo de Requisição**:
     ```bash
     curl -X POST "http://127.0.0.1:8000/users/" -H "Content-Type: application/json" -d '{"username": "joao.silva", "password": "senha123"}'
     ```
   - **Resposta**:
     ```json
     {
       "access_token": "<token_jwt>",
       "token_type": "bearer"
     }
     ```

2. **POST /token**:
   - **Descrição**: Aut lancementica um usuário e retorna um token JWT.
   - **Exemplo de Requisição**:
     ```bash
     curl -X POST "http://127.0.0.1:8000/token" -H "Content-Type: application/x-www-form-urlencoded" -d "username=joao.silva&password=senha123"
     ```
   - **Resposta**:
     ```json
     {
       "access_token": "<token_jwt>",
       "token_type": "bearer"
     }
     ```

3. **POST /accounts/{account_id}/transactions/**:
   - **Descrição**: Cria uma transação (depósito ou saque) para uma conta específica. Requer autenticação.
   - **Exemplo de Requisição**:
     ```bash
     curl -X POST "http://127.0.0.1:8000/accounts/1/transactions/" -H "Authorization: Bearer <token_jwt>" -H "Content-Type: application/json" -d '{"type": "deposit", "amount": 100.50}'
     ```
   - **Resposta**:
     ```json
     {
       "id": 1,
       "type": "deposit",
       "amount": 100.50,
       "timestamp": "2025-07-03T14:00:00"
     }
     ```

4. **GET /accounts/{account_id}/**:
   - **Descrição**: Retorna os detalhes da conta, incluindo saldo e extrato de transações. Requer autenticação.
   - **Exemplo de Requisição**:
     ```bash
     curl -X GET "http://127.0.0.1:8000/accounts/1/" -H "Authorization: Bearer <token_jwt>"
     ```
   - **Resposta**:
     ```json
     {
       "id": 1,
       "balance": 100.50,
       "transactions": [
         {
           "id": 1,
           "type": "deposit",
           "amount": 100.50,
           "timestamp": "2025-07-03T14:00:00"
         }
       ]
     }
     ```

### Autenticação
- Os endpoints `/accounts/{account_id}/transactions/` e `/accounts/{account_id}/` requerem um token JWT no cabeçalho `Authorization: Bearer <token>`.
- Obtenha o token via `/token` ou `/users/`.

## Licença

Este projeto é licenciado sob a [Licença MIT](LICENSE).

## Contato

Para dúvidas ou contribuições, entre em contato:
- **Email**: suporte@bankapi.com
- **GitHub Issues**: [Crie uma issue no repositório](#)