import {
  useForm as useHookForm,
  UseFormProps,
  FieldValues,
  Resolver,
} from "react-hook-form"; // RHF TS types :contentReference[oaicite:5]{index=5}
import { zodResolver } from "@hookform/resolvers/zod"; // Zod‑RHF bridge :contentReference[oaicite:6]{index=6}
import { ZodType } from "zod"; // Zod core class :contentReference[oaicite:7]{index=7}

export function useForm<
  TFieldValues extends FieldValues,
  Schema extends ZodType<TFieldValues, TFieldValues>,
>(schema: Schema, options?: Omit<UseFormProps<TFieldValues>, "resolver">) {
  return useHookForm<TFieldValues>({
    ...options,
    resolver: zodResolver(schema) as unknown as Resolver<TFieldValues, unknown>,
  });
}
