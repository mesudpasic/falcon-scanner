<script setup>
import { ref } from "vue";

defineProps({
  text: { type: String, required: true },
});

const visible = ref(false);
</script>

<template>
  <span
    class="help-tip ms-1"
    :aria-label="text"
    role="img"
    tabindex="0"
    @mouseenter="visible = true"
    @mouseleave="visible = false"
    @focus="visible = true"
    @blur="visible = false"
  >
    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true">
      <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16" />
      <path d="m8.93 6.588-2.29.287-.082.38.45.083c.294.07.352.176.288.469l-.738 3.468c-.194.897.105 1.319.808 1.319.545 0 .875-.252 1.02-.598l.088-.416c-.07.176-.246.28-.404.28-.176 0-.246-.105-.176-.35l1.1-4.92zM9 4.5a1 1 0 1 1-2 0 1 1 0 0 1 2 0" />
    </svg>
    <span v-if="visible" class="help-tooltip" role="tooltip">{{ text }}</span>
  </span>
</template>
