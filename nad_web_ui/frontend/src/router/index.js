/**
 * Vue Router 配置
 */
import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('@/views/Dashboard.vue'),
    meta: { title: '異常檢測' }
  },
  {
    path: '/training',
    name: 'Training',
    component: () => import('@/views/Training.vue'),
    meta: { title: '模型訓練' }
  },
  {
    path: '/analysis',
    name: 'IPAnalysis',
    component: () => import('@/views/IPAnalysis.vue'),
    meta: { title: 'IP 分析' }
  },
  {
    path: '/ai-beta',
    name: 'ai-beta',
    component: () => import('@/views/AIBetaTest.vue'),
    meta: { title: 'AI Beta 測試' }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 路由守衛：設置頁面標題
router.beforeEach((to, from, next) => {
  document.title = to.meta.title ? `${to.meta.title} - NAD Web UI` : 'NAD Web UI'
  next()
})

export default router
