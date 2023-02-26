import bcrypt from "bcrypt";
import { SignJWT, jwtVerify } from "jose";
import { db } from "./db";

export const hashPassword = (password) => bcrypt.hash(password, 10);

export const comparePasswords = (plainTextPassword, hashPassword) =>
  bcrypt.compare(plainTextPassword, hashPassword);

// Taking an object/payload -> Transfer to standard string that is unique
// To determine if you allow who you're
export const createJWT = (user) => {
  // return jwt.sign({id: user.id}, 'cookies)
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 60 * 60 * 24 * 7;

  return new SignJWT({ payload: { id: user.id, email: user.email } })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setExpirationTime(exp)
    .setIssuedAt(iat)
    .setNotBefore(iat)
    .sign(new TextEncoder().encode(process.env.JWT_SECRET));
};

// Validate the JWT
export const validateJWT = async (jwt: string) => {
  const { payload } = await jwtVerify(
    jwt,
    new TextEncoder().encode(process.env.JWT_SECRET)
  );

  return payload.payload as any;
};

// Get JWT from cookies
export const getUserFromCookie = async (cookies) => {
  const jwt = cookies.get(process.env.COOKIE_NAME);

  const { id } = await validateJWT(jwt.value);

  const user = await db.user.findUnique({
    where: {
      id: id as string,
    },
  });

  return user;
};
