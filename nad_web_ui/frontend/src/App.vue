<template>
  <el-container class="app-container">
    <!-- 側邊欄 -->
    <el-aside width="200px" class="app-aside">
      <div class="app-title">
        <h2>NAD Web UI</h2>
        <p>網路異常檢測系統</p>
      </div>

      <el-menu
        :default-active="$route.path"
        router
        class="app-menu"
      >
        <el-menu-item index="/">
          <el-icon><Monitor /></el-icon>
          <span>異常檢測</span>
        </el-menu-item>

        <el-menu-item index="/training">
          <el-icon><Setting /></el-icon>
          <span>模型訓練</span>
        </el-menu-item>

        <el-menu-item index="/analysis">
          <el-icon><Search /></el-icon>
          <span>IP 分析</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <!-- 主內容區 -->
    <el-container>
      <el-header class="app-header">
        <h1>{{ currentTitle }}</h1>
      </el-header>

      <el-main class="app-main">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { Monitor, Setting, Search } from '@element-plus/icons-vue'

const route = useRoute()

const currentTitle = computed(() => {
  return route.meta.title || 'NAD Web UI'
})
</script>

<style scoped>
.app-container {
  height: 100vh;
  background-color: #f0f2f5;
}

.app-aside {
  background-color: #001529;
  color: white;
  overflow-y: auto;
}

.app-title {
  padding: 20px;
  text-align: center;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.app-title h2 {
  margin: 0;
  color: #fff;
  font-size: 20px;
}

.app-title p {
  margin: 5px 0 0 0;
  color: rgba(255, 255, 255, 0.6);
  font-size: 12px;
}

.app-menu {
  border-right: none;
  background-color: transparent;
}

.app-menu :deep(.el-menu-item) {
  color: rgba(255, 255, 255, 0.8);
}

.app-menu :deep(.el-menu-item:hover) {
  background-color: rgba(255, 255, 255, 0.1);
  color: #fff;
}

.app-menu :deep(.el-menu-item.is-active) {
  background-color: #1890ff;
  color: #fff;
}

.app-header {
  background-color: white;
  box-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
  display: flex;
  align-items: center;
  padding: 0 24px;
}

.app-header h1 {
  margin: 0;
  font-size: 20px;
  font-weight: 500;
  color: #262626;
}

.app-main {
  padding: 24px;
  overflow-y: auto;
  max-width: none;
  width: 100%;
}

/* 頁面切換動畫 */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
