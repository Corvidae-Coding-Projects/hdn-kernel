# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_SECURITY_HARDENING) += core.o
obj-$(CONFIG_SECURITY_HARDENING) += capabilities.o
obj-$(CONFIG_SECURITY_HARDENING_ARCH_CONTRACT_TEST) += capabilities_test.o
obj-$(CONFIG_SECURITY_HARDENING_AUTOSLAB_TEST) += autoslab_test.o
obj-$(CONFIG_SECURITY_HARDENING_AUTOSLAB_MODULE_TEST) += autoslab_test_module.o
ifeq ($(CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST),y)
obj-m += jitter_test_module.o
endif
obj-$(CONFIG_SECURITY_HARDENING_KERNSEAL) += seal.o
ifeq ($(CONFIG_SECURITY_HARDENING_KERNSEAL_TEST),y)
obj-y += seal_test.o
obj-m += seal_test_module.o
endif
ifeq ($(CONFIG_SECURITY_HARDENING_CONSTIFY_TEST),y)
obj-m += constify_target_module.o
obj-m += constify_test_module.o
endif
obj-$(CONFIG_SECURITY_HARDENING_LATENT_ENTROPY) += latent_entropy.o
obj-$(CONFIG_SECURITY_HARDENING_LATENT_ENTROPY_TEST) += latent_entropy_test.o
obj-$(CONFIG_GCC_PLUGIN_HDN_LIFETIME_FIXTURE) += lifetime_fixture.o
obj-$(CONFIG_GCC_PLUGIN_HDN_LIFETIME_FIXTURE) += lifetime_cross_def.o
obj-$(CONFIG_GCC_PLUGIN_HDN_LIFETIME_BAD_FIXTURE) += lifetime_cross_use.o
ifneq ($(CONFIG_SECURITY_HARDENING_KERNEL_WX_TEST),)
# Keep unexported MM APIs private: only the test suite is exposed to its loader.
obj-y += kernexec_test.o
obj-$(CONFIG_SECURITY_HARDENING_KERNEL_WX_TEST) += kernexec_test_module.o
endif

ifeq ($(CONFIG_SECURITY_HARDENING_PGTABLE_TEST),y)
obj-y += pgtable_test.o
obj-m += pgtable_test_module.o
endif
obj-$(CONFIG_SECURITY_HARDENING_EFI_TEST) += efi_test_module.o
ifeq ($(CONFIG_SECURITY_HARDENING_UDEREF_TEST),y)
obj-y += uderef_test.o
obj-m += uderef_test_module.o
endif
ifeq ($(CONFIG_SECURITY_HARDENING_RAP_ERROR_TEST),y)
obj-y += rap_error_test.o
obj-m += rap_error_test_module.o
endif
ifeq ($(CONFIG_SECURITY_HARDENING_RAP_TEST),y)
obj-m += rap_test_module.o
endif
ifeq ($(CONFIG_SECURITY_HARDENING_RESPECTRE_TEST),y)
obj-m += respectre_test_module.o
endif
ifeq ($(CONFIG_SECURITY_HARDENING_BPF_EXECMEM_TEST),y)
obj-y += bpf_execmem_test.o
obj-m += bpf_execmem_test_module.o
endif
ifeq ($(CONFIG_SECURITY_HARDENING_KVM_STATE_TEST),y)
obj-y += kvm_state_test.o
obj-m += kvm_state_test_module.o
endif
ifeq ($(CONFIG_SECURITY_HARDENING_PRIVATE_STACKS_TEST),y)
obj-y += private_stack_test.o
obj-m += private_stack_test_module.o
endif
