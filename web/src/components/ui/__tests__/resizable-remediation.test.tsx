/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { createRef } from 'react'
import type { GroupImperativeHandle } from 'react-resizable-panels'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from '../resizable'

// jsdom has no CSS layout engine. Supply only browser geometry for a 1010px
// horizontal flex group: 1000px of panels plus a 10px separator. Panel geometry
// follows the real library's rendered flex weights; no layout/constraint or
// pointer behavior is replaced. ResizeObserver is the shared setup's no-op:
// this fixed-size fixture does not exercise container resizing.
function panelRect(element: HTMLElement): DOMRect {
  if (element.hasAttribute('data-group')) return new DOMRect(0, 0, 1010, 200)
  const group = element.closest('[data-group]')
  if (!group) return new DOMRect()
  const panels = [...group.querySelectorAll<HTMLElement>('[data-panel]')]
  const total = panels.reduce(
    (sum, panel) => sum + Number(panel.style.flexGrow || 1),
    0
  )
  const firstWidth = (1000 * Number(panels[0].style.flexGrow || 1)) / total
  if (element.getAttribute('role') === 'separator') {
    return new DOMRect(firstWidth, 0, 10, 200)
  }
  if (element === panels[0]) return new DOMRect(0, 0, firstWidth, 200)
  if (element === panels[1]) {
    return new DOMRect(firstWidth + 10, 0, 1000 - firstWidth, 200)
  }
  return new DOMRect()
}

beforeEach(() => {
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(
    function (this: HTMLElement) {
      return panelRect(this)
    }
  )
  vi.spyOn(HTMLElement.prototype, 'offsetLeft', 'get').mockImplementation(
    function (this: HTMLElement) {
      return panelRect(this).x
    }
  )
  vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockImplementation(
    function (this: HTMLElement) {
      return panelRect(this).width
    }
  )
  vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockImplementation(
    function (this: HTMLElement) {
      return panelRect(this).height
    }
  )
})

afterEach(() => vi.restoreAllMocks())

it('dragging the real separator redistributes panels and stops at both size limits', async () => {
  const groupRef = createRef<GroupImperativeHandle>()
  render(
    <ResizablePanelGroup groupRef={groupRef} orientation='horizontal'>
      <ResizablePanel
        id='left'
        role='region'
        aria-label='Left pane'
        defaultSize='50%'
        minSize='25%'
        maxSize='70%'
      >
        Left pane
      </ResizablePanel>
      <ResizableHandle aria-label='Resize panes' />
      <ResizablePanel
        id='right'
        role='region'
        aria-label='Right pane'
        defaultSize='50%'
        minSize='30%'
      >
        Right pane
      </ResizablePanel>
    </ResizablePanelGroup>
  )
  const handle = screen.getByRole('separator', { name: 'Resize panes' })
  await waitFor(() =>
    expect(groupRef.current?.getLayout()).toEqual({ left: 50, right: 50 })
  )
  await waitFor(() => expect(handle).toHaveAttribute('aria-valuenow', '50'))

  // Coordinates are real pointer inputs, not calls to the imperative resize API.
  fireEvent.pointerDown(handle, {
    pointerId: 1,
    pointerType: 'mouse',
    button: 0,
    buttons: 1,
    clientX: 505,
    clientY: 100,
  })
  fireEvent.pointerMove(document, {
    pointerId: 1,
    pointerType: 'mouse',
    buttons: 1,
    clientX: 605,
    clientY: 100,
  })
  await waitFor(() =>
    expect(groupRef.current?.getLayout()).toEqual({ left: 60, right: 40 })
  )
  expect(handle).toHaveAttribute('aria-valuenow', '60')
  expect(screen.getByRole('region', { name: 'Left pane' })).toHaveStyle({
    flexGrow: '60',
  })

  fireEvent.pointerMove(document, {
    pointerId: 1,
    pointerType: 'mouse',
    buttons: 1,
    clientX: 1005,
    clientY: 100,
  })
  await waitFor(() =>
    expect(groupRef.current?.getLayout()).toEqual({ left: 70, right: 30 })
  )
  expect(handle).toHaveAttribute('aria-valuenow', '70')

  fireEvent.pointerMove(document, {
    pointerId: 1,
    pointerType: 'mouse',
    buttons: 1,
    clientX: 5,
    clientY: 100,
  })
  await waitFor(() =>
    expect(groupRef.current?.getLayout()).toEqual({ left: 25, right: 75 })
  )
  fireEvent.pointerUp(document, {
    pointerId: 1,
    pointerType: 'mouse',
    button: 0,
    buttons: 0,
    clientX: 5,
    clientY: 100,
  })
  expect(handle).toHaveAttribute('aria-valuenow', '25')
  expect(screen.getByRole('region', { name: 'Right pane' })).toHaveStyle({
    flexGrow: '75',
  })

  handle.focus()
  fireEvent.keyDown(handle, { key: 'ArrowRight' })
  await waitFor(() =>
    expect(groupRef.current?.getLayout()).toEqual({ left: 30, right: 70 })
  )
  expect(handle).toHaveFocus()
  expect(handle).toHaveAttribute('aria-valuenow', '30')
})
