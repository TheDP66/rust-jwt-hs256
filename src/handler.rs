use crate::{
    jwt_auth,
    model::{LoginUserSchema, RegisterUserSchema, User},
    response::FilteredUser,
    token, AppState,
};
use actix_web::{
    cookie::{time::Duration as ActixWebDuration, Cookie},
    get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{prelude::*, Duration};
use jsonwebtoken::{encode, EncodingKey, Header};
use redis::{AsyncCommands, RedisResult};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_owned(),
        name: user.name.to_owned(),
        photo: user.photo.to_owned(),
        role: user.role.to_owned(),
        verified: user.verified,
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}

#[post("/auth/register")]
async fn register_user_handler(
    body: web::Json<RegisterUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    // check if email user exists
    let exists = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(body.email.to_owned())
        .fetch_one(&data.db)
        .await
        .unwrap()
        .get(0);

    // if exists, cant register
    if exists {
        return HttpResponse::Conflict().json(
            serde_json::json!({"status": "fail","message": "User with that email already exists"}),
        );
    }

    // generate a random Base64-encoded
    let salt = SaltString::generate(&mut OsRng);

    // hashing user password
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .expect("Error while hashing password")
        .to_string();

    // insert user data to db
    let query_result = sqlx::query_as!(
        User,
        "INSERT INTO users (name,email,password) VALUES ($1, $2, $3) RETURNING *",
        body.name.to_string(),
        body.email.to_string().to_lowercase(),
        hashed_password
    )
    .fetch_one(&data.db)
    .await;

    match query_result {
        Ok(user) => {
            let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "user": filter_user_record(&user)
            })});

            return HttpResponse::Ok().json(user_response);
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format!("{:?}", e)}));
        }
    }
}

#[post("/auth/login")]
async fn login_user_handler(
    body: web::Json<LoginUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    // get user by email
    let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", body.email)
        .fetch_optional(&data.db)
        .await
        .unwrap();

    // check query result
    let user = match query_result {
        Some(user) => user,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!(
                {
                    "status":"fail",
                    "message": "Invalid email or password"
                }
            ));
        }
    };

    // hash and verify input password
    let is_valid = PasswordHash::new(&user.password)
        .and_then(|parsed_hash| {
            Argon2::default().verify_password(body.password.as_bytes(), &parsed_hash)
        })
        .map_or(false, |_| true);

    // check is valid
    if !is_valid {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "status": "fail",
            "message": "Invalid email or password"
        }));
    }

    // generate access token
    let access_token_details = match token::generate_jwt_token(
        user.id,
        data.env.access_token_max_age,
        data.env.access_token_private_key.to_owned(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "status": "fail",
                "message": format_args!("{}", e)
            }))
        }
    };

    // generate refresh token
    let refresh_token_details = match token::generate_jwt_token(
        user.id,
        data.env.refresh_token_max_age,
        data.env.refresh_token_private_key.to_owned(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "status": "fail",
                "message": format_args!("{}", e)
            }));
        }
    };

    // connect to redis
    let mut redis_client = match data.redis_client.get_async_connection().await {
        Ok(redis_client) => redis_client,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status":"fail",
                "message": format_args!("{}", e)
            }));
        }
    };

    // set value and exp access key
    let access_result: redis::RedisResult<()> = redis_client
        .set_ex(
            access_token_details.token_uuid.to_string(),
            user.id.to_string(),
            (data.env.access_token_max_age * 60) as u64,
        )
        .await;

    // check if result error
    if let Err(e) = access_result {
        return HttpResponse::UnprocessableEntity().json(serde_json::json!({
            "status":"error",
            "message":format_args!("{}", e)
        }));
    }

    // set value and exp refresh key
    let refresh_result: redis::RedisResult<()> = redis_client
        .set_ex(
            refresh_token_details.token_uuid.to_string(),
            user.id.to_string(),
            (data.env.refresh_token_max_age * 60) as u64,
        )
        .await;

    // check if result error
    if let Err(e) = refresh_result {
        return HttpResponse::UnprocessableEntity().json(serde_json::json!({
        "status":"error","message":format_args!("{}", e)
        }));
    }

    // build token cookies
    let access_cookie = Cookie::build("access_token", access_token_details.token.clone().unwrap())
        .path("/")
        .max_age(ActixWebDuration::new(data.env.access_token_max_age * 60, 0))
        .http_only(true)
        .finish();
    let refresh_cookie = Cookie::build(
        "refresh_token",
        refresh_token_details.token.clone().unwrap(),
    )
    .path("/")
    .max_age(ActixWebDuration::new(
        data.env.refresh_token_max_age * 60,
        0,
    ))
    .http_only(true)
    .finish();
    let logged_in_cookie = Cookie::build("logged_in", "true")
        .path("/")
        .max_age(ActixWebDuration::new(data.env.access_token_max_age * 60, 0))
        .http_only(false)
        .finish();

    // send access_token response
    HttpResponse::Ok()
        .cookie(access_cookie)
        .cookie(refresh_cookie)
        .cookie(logged_in_cookie)
        .json(serde_json::json!({
            "status": "success",
            "access_token": access_token_details.token.unwrap()
        }))
}

#[get("/auth/refresh")]
async fn refresh_access_token_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> impl Responder {
    let message = "could not refresh access token";

    // check request refresh_token
    let refresh_token = match req.cookie("refresh_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "status" : "fail",
                "message": message
            }));
        }
    };

    // check request refresh_token detail
    let refresh_token_details =
        match token::verify_jwt_token(data.env.refresh_token_public_key.to_owned(), &refresh_token)
        {
            Ok(token_details) => token_details,
            Err(e) => {
                return HttpResponse::Forbidden().json(
                    serde_json::json!({"status": "fail", "message": format_args!("{:?}", e)}),
                );
            }
        };

    // check redis connection
    let result = data.redis_client.get_async_connection().await;
    let mut redis_client = match result {
        Ok(redis_client) => redis_client,
        Err(e) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "status":"fail",
                "message":format!("Could not connect to Redis: {}", e)
            }));
        }
    };

    // get data from redis using refresh token
    let redis_result: redis::RedisResult<String> = redis_client
        .get(refresh_token_details.token_uuid.to_string())
        .await;

    // get user_id from token
    let user_id = match redis_result {
        Ok(value) => value,
        Err(_) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "status": "fail",
                "message": message
            }))
        }
    };

    // parse user_id
    let user_id_uuid = Uuid::parse_str(&user_id).unwrap();
    // select user by id
    let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id_uuid)
        .fetch_optional(&data.db)
        .await
        .unwrap();

    // check result
    if query_result.is_none() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "status":"fail",
            "message":"the user belonging to this token no logger exists"
        }));
    }

    let user = query_result.unwrap();

    // generate access token
    let access_token_details = match token::generate_jwt_token(
        user.id,
        data.env.access_token_max_age,
        data.env.access_token_private_key.to_owned(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            return HttpResponse::BadGateway()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{:?}", e)}));
        }
    };

    // store access token to redis
    let redis_result: redis::RedisResult<()> = redis_client
        .set_ex(
            access_token_details.token_uuid.to_string(),
            user.id.to_string(),
            (data.env.access_token_max_age * 60) as u64,
        )
        .await;

    // check if storing error
    if redis_result.is_err() {
        return HttpResponse::UnprocessableEntity().json(
            serde_json::json!({"status": "error", "message": format_args!("{:?}", redis_result.unwrap_err())}),
        );
    }

    // set access_token in http_only
    let access_cookie = Cookie::build("access_token", access_token_details.token.clone().unwrap())
        .path("/")
        .max_age(ActixWebDuration::new(data.env.access_token_max_age * 60, 0))
        .http_only(true)
        .finish();

    let logged_in_cookie = Cookie::build("logged_in", "true")
        .path("/")
        .max_age(ActixWebDuration::new(data.env.access_token_max_age * 60, 0))
        .http_only(false)
        .finish();

    // send access_token response
    HttpResponse::Ok()
        .cookie(access_cookie)
        .cookie(logged_in_cookie)
        .json(serde_json::json!({
            "status": "success",
            "access_token": access_token_details.token.unwrap()
        }))
}

#[get("/auth/logout")]
async fn logout_handler(
    req: HttpRequest,
    auth_guard: jwt_auth::JwtMiddleware,
    data: web::Data<AppState>,
) -> impl Responder {
    let message = "Token is invalid or session has expired";

    // check refresh_token in req
    let refresh_token = match req.cookie("refresh_token") {
        Some(c) => c.value().to_string(),
        None => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"status": "fail", "message": message}));
        }
    };

    // get refresh token detail
    let refresh_token_details =
        match token::verify_jwt_token(data.env.refresh_token_public_key.to_owned(), &refresh_token)
        {
            Ok(token_details) => token_details,
            Err(e) => {
                return HttpResponse::Forbidden().json(
                    serde_json::json!({"status": "fail", "message": format_args!("{:?}", e)}),
                );
            }
        };

    // check redis connection
    let mut redis_client = data.redis_client.get_async_connection().await.unwrap();
    // delete token in redis
    let redis_result: redis::RedisResult<usize> = redis_client
        .del(&[
            refresh_token_details.token_uuid.to_string(),
            auth_guard.access_token_uuid.to_string(),
        ])
        .await;

    // check is error
    if redis_result.is_err() {
        return HttpResponse::UnprocessableEntity().json(serde_json::json!({
            "status": "error",
            "message": format_args!("{:?}", redis_result.unwrap_err())
        }));
    }

    // force token expired
    let access_cookie = Cookie::build("access_token", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();
    let refresh_cookie = Cookie::build("refresh_token", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();
    let logged_in_cookie = Cookie::build("logged_in", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();

    HttpResponse::Ok()
        .cookie(access_cookie)
        .cookie(refresh_cookie)
        .cookie(logged_in_cookie)
        .json(serde_json::json!({"status": "success"}))
}

pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api")
        // .service(health_checker_handler)
        .service(refresh_access_token_handler)
        // .service(logout_handler)
        // .service(get_me_handler)
        .service(register_user_handler)
        .service(login_user_handler);

    conf.service(scope);
}
