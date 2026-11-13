import { createSSRApp } from 'vue'
import VConsole from 'vconsole'
import App from './App.vue'

new VConsole()
uni.setEnableDebug({ enableDebug: true })

export function createApp() {
  return { app: createSSRApp(App) }
}
