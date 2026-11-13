const BASE_URL = import.meta.env.VITE_API_BASE || 'https://api.example.com'

export function request(path) {
  return uni.request({ url: BASE_URL + path })
}
