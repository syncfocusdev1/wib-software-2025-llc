<template>
	<div class="card">
		<h2>Firewall</h2>
		<div style="display:flex; gap:8px;">
			<input v-model="target" placeholder="IP or domain" />
			<button @click="block">Block</button>
		</div>
	</div>
	<div class="card" style="margin-top:12px;">
		<h3>Rules</h3>
		<ul>
			<li v-for="r in rules" :key="r">{{ r }}</li>
		</ul>
	</div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
const target = ref('');
const rules = ref<string[]>([]);
function block(){
	rules.value.push(`Blocked ${target.value}`);
	target.value = '';
}
</script>