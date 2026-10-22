import { redirect } from "next/navigation";

export default function Dashboard() {
  // The legacy "Command Dashboard" mock displayed fabricated findings, which
  // violates the platform's no-fabrication rule. Route to the real, live-data
  // workspace until this surface is genuinely built.
  redirect("/app");
}
