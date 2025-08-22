<template>
	<div class="card">
		<h2>Settings</h2>
		<label>
			Theme
			<select v-model="theme">
				<option value="dark">Dark</option>
				<option value="light">Light</option>
			</select>
		</label>
		<div style="margin-top:8px;">
			<button @click="checkUpdate">Check for Updates</button>
			<p v-if="update">Latest: {{ update }}</p>
		</div>
	</div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
const theme = ref<'dark'|'light'>('dark');
const update = ref('');
async function checkUpdate(){
	update.value = 'v0.1.0 (demo)';
}
</script>