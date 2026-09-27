export type ActionState = {
  status: "idle" | "error";
  message: string | null;
  field?: "email" | "organization_name" | "password";
};

export const initialActionState: ActionState = {
  status: "idle",
  message: null,
};
