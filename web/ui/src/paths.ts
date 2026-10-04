// The last two path segments are what a reader needs; the full path goes in the
// tooltip.
export function shortPath(file: string): string {
  const parts = file.split('/')
  return parts.length > 2 ? parts.slice(-2).join('/') : file
}
