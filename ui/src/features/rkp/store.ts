import { defineStore } from "pinia"
import { computed, ref, watch } from "vue"

import type { ImportDraft, ImportResult, Info, Keybox, Provision, Verify } from "./api"
import { hasImportFiles, rkpApi } from "./api"
import type { Draft } from "./draft"
import { applyDetected, hasGenericDevice, toDraft, toProfile } from "./draft"

/** Profile draft and the latest results, shared by every RKP tab. */
export const useRkpStore = defineStore("rkp", () => {
  const draft = ref<Draft | null>(null)
  const secretsPath = ref("")
  const info = ref<Info | null>(null)
  const provision = ref<Provision | null>(null)
  const keybox = ref<Keybox | null>(null)
  const verify = ref<Verify | null>(null)
  const verifyPath = ref("")
  const importDraft = ref<ImportDraft>({
    mode: "bundle",
    bundlePath: "",
    chainPath: "",
    signingPath: "",
    configPath: "",
  })
  const importResult = ref<ImportResult | null>(null)
  const importBusy = ref(false)
  const importReady = ref(false)
  const importComplete = computed(() => hasImportFiles(importDraft.value))
  let importRevision = 0

  watch(
    importDraft,
    () => {
      importRevision++
      importResult.value = null
      importReady.value = false
    },
    { deep: true, flush: "sync" },
  )
  watch(
    draft,
    () => {
      info.value = provision.value = keybox.value = null
    },
    { deep: true, flush: "sync" },
  )
  watch(verifyPath, () => (verify.value = null), { flush: "sync" })

  async function runImport(action: "validate" | "diagnose" | "issue") {
    if (importBusy.value || !importComplete.value || (action === "issue" && !importReady.value)) {
      return
    }
    const revision = importRevision
    const input = { ...importDraft.value }
    importBusy.value = true
    importResult.value = null
    try {
      const result = await {
        validate: rkpApi.importValidate,
        diagnose: rkpApi.importDiagnose,
        issue: rkpApi.importIssue,
      }[action](input)
      if (revision === importRevision) {
        importResult.value = result
        if (result.stage === "validated") importReady.value = result.ready_for_issuance
      }
    } catch (error) {
      importReady.value = false
      throw error
    } finally {
      importBusy.value = false
    }
  }

  async function load() {
    const shown = await rkpApi.show()
    secretsPath.value = shown.paths.profile_secrets_path
    let next = toDraft(shown.profile)
    if (hasGenericDevice(next)) {
      next = applyDetected(next, (await rkpApi.detect()).profile)
    }
    draft.value = next
  }

  async function save() {
    if (!draft.value) return
    const saved = await rkpApi.save(toProfile(draft.value))
    secretsPath.value = saved.paths.profile_secrets_path
    draft.value = toDraft(saved.profile)
  }

  async function detect() {
    if (!draft.value) return
    draft.value = applyDetected(draft.value, (await rkpApi.detect()).profile)
  }

  async function clear() {
    await rkpApi.clear()
    info.value = provision.value = keybox.value = verify.value = null
    await load()
  }

  /** Every action runs against the saved profile, so unsaved edits are saved first. */
  async function run<T>(action: () => Promise<T>) {
    await save()
    return action()
  }

  return {
    draft,
    secretsPath,
    info,
    provision,
    keybox,
    verify,
    verifyPath,
    importDraft,
    importResult,
    importBusy,
    importReady,
    importComplete,
    validateImport: () => runImport("validate"),
    diagnoseImport: () => runImport("diagnose"),
    issueImport: () => runImport("issue"),
    load,
    save,
    detect,
    clear,
    checkKey: async () => (info.value = await run(rkpApi.info)),
    runProvision: async () => {
      provision.value = await run(() => rkpApi.provision())
      verifyPath.value = provision.value.csr_path
    },
    runKeybox: async () => {
      keybox.value = await run(rkpApi.keybox)
      verifyPath.value = keybox.value.csr_path
    },
    runVerify: async () => (verify.value = await rkpApi.verify(verifyPath.value.trim())),
  }
})
