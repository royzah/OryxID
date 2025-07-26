import {
  useMutation,
  useQueryClient,
  UseMutationOptions,
} from "@tanstack/react-query";

interface OptimisticMutationOptions<TData, TError, TVariables, TContext>
  extends UseMutationOptions<TData, TError, TVariables, TContext> {
  queryKey: unknown[];
  updateFn: (old: TData | undefined, variables: TVariables) => TData;
}

export function useOptimisticMutation<
  TData = unknown,
  TError = unknown,
  TVariables = void,
  TContext = unknown,
>({
  queryKey,
  updateFn,
  ...options
}: OptimisticMutationOptions<TData, TError, TVariables, TContext>) {
  const queryClient = useQueryClient();

  return useMutation<TData, TError, TVariables, TContext>({
    ...options,
    onMutate: async (variables) => {
      await queryClient.cancelQueries({ queryKey });
      const previousData = queryClient.getQueryData<TData>(queryKey);

      queryClient.setQueryData(queryKey, (old: TData | undefined) =>
        updateFn(old, variables),
      );

      if (options.onMutate) {
        return options.onMutate(variables);
      }

      return { previousData } as unknown as TContext;
    },
    onError: (error, variables, context) => {
      if (context && typeof context === "object" && "previousData" in context) {
        queryClient.setQueryData(queryKey, context.previousData);
      }
      if (options.onError) {
        options.onError(error, variables, context);
      }
    },
    onSettled: (data, error, variables, context) => {
      queryClient.invalidateQueries({ queryKey });
      if (options.onSettled) {
        options.onSettled(data, error, variables, context);
      }
    },
  });
}
