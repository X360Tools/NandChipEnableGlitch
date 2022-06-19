/*
 * Copyright (c) 2022 Balázs Triszka <balika011@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hardware/vreg.h"
#include "hardware/clocks.h"
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "glitch.pio.h"

#define GLTICH 11
#define CPU_PLL_BYPASS 12
#define SMC_RESET_CPU 13
#define CPU_RST_N 14
#define FLSH_CE_N 15

#define DEBUG_LED 25

int glitches[400];

int main(void)
{
	vreg_set_voltage(VREG_VOLTAGE_1_30);
	set_sys_clock_khz(266000, true);

	uint32_t freq = clock_get_hz(clk_sys);
	clock_configure(clk_peri, 0, CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLK_SYS, freq, freq);

	gpio_init(CPU_RST_N);
	gpio_set_dir(CPU_RST_N, GPIO_IN);
	gpio_set_slew_rate(CPU_RST_N, GPIO_SLEW_RATE_FAST);
	gpio_set_drive_strength(CPU_RST_N, GPIO_DRIVE_STRENGTH_12MA);

	gpio_init(DEBUG_LED);
	gpio_set_dir(DEBUG_LED, GPIO_OUT);

	uint offset = pio_add_program(pio0, &glitch_program);
	pio_sm_config c = glitch_program_get_default_config(offset);
	sm_config_set_sideset_pins(&c, GLTICH);

	pio_gpio_init(pio0, GLTICH);
	gpio_set_slew_rate(GLTICH, GPIO_SLEW_RATE_FAST);
	gpio_set_drive_strength(GLTICH, GPIO_DRIVE_STRENGTH_12MA);

	pio_gpio_init(pio0, CPU_PLL_BYPASS);
	gpio_set_slew_rate(CPU_PLL_BYPASS, GPIO_SLEW_RATE_FAST);
	gpio_set_drive_strength(CPU_PLL_BYPASS, GPIO_DRIVE_STRENGTH_12MA);

	pio_sm_set_pins_with_mask(pio0, 0, (0u << GLTICH) | (0u << CPU_PLL_BYPASS), (1u << GLTICH) | (1u << CPU_PLL_BYPASS));
	pio_sm_set_pindirs_with_mask(pio0, 0, (1u << GLTICH) | (1u << CPU_PLL_BYPASS), (1u << GLTICH) | (1u << CPU_PLL_BYPASS));

	pio_sm_init(pio0, 0, offset, &c);

	gpio_init(SMC_RESET_CPU);
	gpio_set_dir(SMC_RESET_CPU, GPIO_OUT);
	gpio_set_slew_rate(SMC_RESET_CPU, GPIO_SLEW_RATE_FAST);
	gpio_set_drive_strength(SMC_RESET_CPU, GPIO_DRIVE_STRENGTH_12MA);

	while (1)
	{
		if (!pio_sm_is_rx_fifo_empty(pio0, 0))
			pio_sm_get(pio0, 0);

		pio_sm_exec(pio0, 0, pio_encode_jmp(offset));

		while (!gpio_get(CPU_RST_N))
			;

		sleep_ms(50);

		pio_sm_set_enabled(pio0, 0, true);

		gpio_put(DEBUG_LED, 1);

		// ---

		// algo: (ms / 1000) * 1000000 * 266

		/*
			CE to target
			11.031106ms - 12.33397ms
			11.031054ms - 12.333918ms
			11.031066ms - 12.333922ms
			11.031092ms - 12.333954ms

			-> 2934246 - 3280817 -> 346571 wiggle
		*/

		pio_sm_put_blocking(pio0, 0, 2934246 + 213328 + 72); // delay_rst BOOTS: 193936 207056 210672 213328

		pio_sm_put_blocking(pio0, 0, 64); // hold_rst

		pio_sm_put_blocking(pio0, 0, 66500); // hold_pll

		// --

		pio_sm_put_blocking(pio0, 0, 0xC000 / 0x200 + 1);

		sleep_ms(50);

		bool need_reset = true;
		if (!pio_sm_is_rx_fifo_empty(pio0, 0))
		{
			pio_sm_get(pio0, 0);
			need_reset = false;
		}

		pio_sm_set_enabled(pio0, 0, false);

		pio_sm_restart(pio0, 0);

		gpio_put(DEBUG_LED, 0);

		if (need_reset)
		{
			gpio_put(SMC_RESET_CPU, 1);
			sleep_ms(10);
			gpio_put(SMC_RESET_CPU, 0);
		}

		while (gpio_get(CPU_RST_N))
			;
	}

	return 0;
}
