declare module "@huggingface/transformers" {
  export function pipeline(
    task: string,
    model: string,
    options?: Record<string, unknown>,
  ): Promise<(texts: string[], options: { pooling: string; normalize: boolean }) => Promise<{ data: Float32Array }>>;
}
