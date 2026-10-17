<script setup lang="ts">
import { useMutation } from "@tanstack/vue-query"
import { FileKey2, HardDriveDownload } from "@lucide/vue"
import { storeToRefs } from "pinia"
import { computed } from "vue"
import { useI18n } from "vue-i18n"

import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import KeyValueList from "@/core/components/KeyValueList.vue"
import SectionCard from "@/core/components/SectionCard.vue"
import type { KeyboxTarget } from "@/core/features"
import { contributions } from "@/core/features"
import { notifySuccess } from "@/core/notify"

import { useRkpI18n } from "../i18n"
import { useRkpStore } from "../store"

const { t } = useRkpI18n()
const global = useI18n()
const store = useRkpStore()
const { keybox } = storeToRefs(store)
// Other tools (the Tricky Store manager) register where a keybox can be installed.
const targets = contributions("keyboxTargets")

const generate = useMutation({
  mutationFn: store.runKeybox,
  onSuccess: () => notifySuccess(t("keybox.done")),
})
const install = useMutation({
  mutationFn: (target: KeyboxTarget) => target.install(keybox.value!.keybox_path),
  onSuccess: (result) =>
    notifySuccess(
      t("keybox.installed", { target: result.targetPath }),
      result.backupPath ? t("keybox.backup", { path: result.backupPath }) : undefined,
    ),
})

const rows = computed(() =>
  keybox.value
    ? [
        { label: t("keybox.path"), value: keybox.value.keybox_path, mono: true, copy: true },
        { label: t("keybox.deviceId"), value: keybox.value.device_id, mono: true },
        { label: t("keybox.csrPath"), value: keybox.value.csr_path, mono: true, copy: true },
        { label: t("keybox.certificates"), value: keybox.value.chain_summary.certificates },
      ]
    : [],
)
</script>

<template>
  <div class="flex flex-col gap-6">
    <p v-if="!keybox" class="text-muted-foreground px-4 text-sm">{{ t("keybox.empty") }}</p>
    <Button size="lg" :disabled="generate.isPending.value" @click="generate.mutate()">
      <Spinner v-if="generate.isPending.value" class="size-6" />
      <FileKey2 v-else />
      {{ t("keybox.generate") }}
    </Button>

    <SectionCard v-if="keybox" :title="t('keybox.path')">
      <div class="flex flex-col gap-4">
        <KeyValueList :rows="rows" />
        <div class="flex flex-col gap-2">
          <Button
            v-for="target in targets"
            :key="target.id"
            variant="secondary"
            :disabled="install.isPending.value"
            @click="install.mutate(target)"
          >
            <HardDriveDownload />
            {{ t("keybox.install", { target: global.t(target.labelKey) }) }}
          </Button>
        </div>
      </div>
    </SectionCard>
  </div>
</template>
