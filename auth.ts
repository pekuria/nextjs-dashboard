import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { User } from "./app/lib/definitions";
import { sql } from "@vercel/postgres";
import bcrypt from 'bcrypt';

async function getUser(email: string): Promise<User | undefined> {
    try {
        const user = await sql<User>`SELECT * FROM USERS WHERE EMAIL=${email}`;
        return user.rows[0];
    } catch(error) {
        console.log('failed to fetch user:', error);
        throw new Error('Failed to fetch user.');
    }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [Credentials({
        async authorize(credentials) {
            const passedCredentials = z
                .object({ email: z.string().email(), password: z.string().min(6) })
                .safeParse(credentials);

            if(passedCredentials.success) {
                const {email, password} = passedCredentials.data;
                const user = await getUser(email);
                if(!user) return null;
                const passwordMatch = await bcrypt.compare(password, user.password);

                if (passwordMatch) return user;
            }
            console.log('Invalid credentials');
            return null;
        },
    }),
    ]
});