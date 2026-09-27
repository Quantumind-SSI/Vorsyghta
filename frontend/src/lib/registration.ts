import { z } from "zod";

const MAX_PASSWORD_BYTES = 72;

export const registrationInputSchema = z.object({
  email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()),
  password: z
    .string()
    .refine((value) => [...value].length >= 12, "Password must contain at least 12 characters")
    .refine((value) => [...value].length <= 72, "Password must not exceed 72 characters")
    .refine(
      (value) => new TextEncoder().encode(value).byteLength <= MAX_PASSWORD_BYTES,
      "Password must not exceed 72 UTF-8 bytes",
    ),
  organization_name: z
    .string()
    .max(120)
    .transform((value) => value.trim().replace(/\s+/g, " "))
    .pipe(z.string().min(2).max(120)),
});

export type RegistrationInput = z.infer<typeof registrationInputSchema>;
export type RegistrationField = keyof RegistrationInput;
