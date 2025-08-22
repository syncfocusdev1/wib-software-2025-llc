<template>
	<div class="app" :class="theme">
		<aside class="sidebar">
			<h1>WhereItBelongs</h1>
			<nav>
				<router-link to="/">Home</router-link>
				<router-link to="/scan">Scan</router-link>
				<router-link to="/unrat">UNRAT</router-link>
				<router-link to="/firewall">Firewall</router-link>
				<router-link to="/privacy">Privacy</router-link>
				<router-link to="/tools">Tools</router-link>
				<router-link to="/settings">Settings</router-link>
				<router-link to="/account">Account</router-link>
			</nav>
		</aside>
		<main>
			<router-view />
		</main>
	</div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
const theme = ref<'light'|'dark'>('dark');
</script>
<style>
:root { color-scheme: dark light; }
body, html, #app { margin: 0; height: 100%; }
.app { display: flex; height: 100%; }
.sidebar { width: 220px; padding: 16px; background: #0f172a; color: #e2e8f0; display: flex; flex-direction: column; gap: 8px; }
.sidebar a { color: #cbd5e1; text-decoration: none; display: block; padding: 6px 8px; border-radius: 6px; }
.sidebar a.router-link-active { background: #1e293b; color: #fff; }
main { flex: 1; padding: 16px; background: var(--bg, #0b1020); color: var(--fg, #e2e8f0); }
</style>