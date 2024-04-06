# Auth microservice

This microservice created for auth of some system as example. It is based on Clean Architecture and uses grpc.

## Documentation

Our microservice based on clean architecture.

We divide our microservice into different layers. Each file in the layer must not overlap.

The first layer is the **repository**: this layer represents the layer that works with the database. We divide our various parts into small fragments. There is also a main repository file that contains all the interfaces of the layer parts for using this instance in the upper layers.

The second level is **entity**: this level simply contains models for development.

The third level is **service**: it also contains the main service that works with repository interfaces. Here in our application we have to use only logic, and we can work with various lower-level repositories. This makes our code more readable and high-quality.

The fourth level is the **controller**: here we keep only API request handlers, such as HTTP or GRPC.

- This project uses postres

## API Reference

#### Register user

```http
  POST /v1/auth/register
```

| Parameter  | Type     | Description                        |
| :--------- | :------- | :--------------------------------- |
| `email`    | `string` | **Required**. Email of the user    |
| `password` | `string` | **Required**. Password of the user |

#### Registrate new user

Return `access_token` and `refresh_token` and `role`

#### Login user

```http
  POST /v1/auth/login
```

| Parameter | Type     | Description                        |
| :-------- | :------- | :--------------------------------- |
| `email`   | `string` | **Required**. Email of the user    |
| `password` | `string` | **Required**. Password of the user |

#### Log in user

Return `access_token` and `refresh_token` and `role`

#### Refresh access token

```http
  POST /v1/auth/refresh
```

| Parameter       | Type     | Description                                  |
| :-------------- | :------- | :------------------------------------------- |
| `refresh_token` | `string` | **Required**. The refresh token              |
| `role`          | `string` | **Required**. Role of the user - USER, ADMIN |

#### Refresh access token

Return `access_token` and `refresh_token`

#### Check is valid token

```http
  POST /v1/auth/check
```

| Parameter | Type     | Description                                  |
| :-------- | :------- | :------------------------------------------- |
| `token`   | `string` | **Required**. The refresh token              |
| `role`    | `string` | **Required**. Role of the user - USER, ADMIN |

#### Return valid of token

Return `valid` **bool** and `user_id` **string**

## Deployment

To deploy this project run

- Create .env file (example of .env you can find in .env_example) in the root and tests folder
- You can set the adjustment of **docker-compose** file and **local.yml**

```bash
  docker compose up --build
```
