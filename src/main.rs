#[macro_use]
extern crate rocket;

pub mod prisma;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use prisma::user;
use rocket::http::{Cookie, CookieJar, Status};
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct Context {
    pub db: Arc<prisma::PrismaClient>,
}

pub type Ctx = rocket::State<Context>;

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let _rocket = rocket::build()
        .mount("/", routes![login, logout, register, me])
        .manage(Context {
            db: Arc::new(
                prisma::new_client()
                    .await
                    .expect("Failed to connect to database"),
            ),
        })
        .launch()
        .await?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct User {
    id: String,
    username: String,
}

#[post("/login", data = "<credentials>")]
async fn login(ctx: &Ctx, cookies: &CookieJar<'_>, credentials: Json<Credentials>) -> Status {
    let user = ctx
        .db
        .user()
        .find_unique(user::username::equals(credentials.username.trim().to_lowercase().clone()))
        .exec()
        .await;
    if let Ok(user) = user {
        match user {
            Some(user) => {
                let password_hash = PasswordHash::new(&user.password).unwrap();

                let password_match = Argon2::default()
                    .verify_password(credentials.password.clone().as_bytes(), &password_hash)
                    .is_ok();

                return if password_match {
                    cookies.add_private(Cookie::new("uid", user.id));

                    Status::Ok
                } else {
                    Status::Unauthorized
                };
            }
            None => Status::NotFound,
        }
    } else {
        Status::InternalServerError
    }
}

#[get("/me")]
async fn me(ctx: &Ctx, cookies: &CookieJar<'_>) -> Option<Json<User>> {
    let user_id = cookies.get_private("uid")?.value().to_string();
    let user = ctx
        .db
        .user()
        .find_unique(user::id::equals(user_id))
        .exec()
        .await
        .unwrap();

    match user {
        Some(user) => Some(Json(User {
            id: user.id,
            username: user.username,
        })),
        None => None,
    }
}

#[post("/logout")]
async fn logout(cookies: &CookieJar<'_>) -> Status {
    let user = cookies.get_private("uid");

    match user {
        Some(_) => {
            cookies.remove_private(Cookie::named("uid"));
            Status::Ok
        }
        None => Status::Unauthorized,
    }
}

#[post("/register", data = "<credentials>")]
async fn register(ctx: &Ctx, credentials: Json<Credentials>) -> Status {
    let check_username_available: Option<user::Data> = ctx
        .db
        .user()
        .find_unique(user::username::equals(credentials.username.trim().to_lowercase().clone()))
        .exec()
        .await
        .unwrap();

    match check_username_available {
        Some(_user) => Status::Conflict,
        None => {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();

            let password_hash = argon2
                .hash_password(credentials.password.clone().as_bytes(), &salt)
                .unwrap()
                .to_string();

            let _new_user = ctx
                .db
                .user()
                .create(credentials.username.trim().to_lowercase().to_owned(), password_hash, vec![])
                .exec()
                .await;
            Status::Created
        }
    }
}
