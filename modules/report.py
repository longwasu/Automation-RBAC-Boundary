import rich
from rich.table import Table
from rbac_matrix import ProbeResult
from typing import List, Dict, Optional, Any
import xml.etree.ElementTree as ET


def render_table(results: List[ProbeResult]):
    if not results:
        print("[*] Không có dữ liệu để hiển thị.")
        return

    # Lọc trùng lặp -> danh sách -> sắp xếp
    groups = sorted(list(set(r.group for r in results)))
    users = sorted(list(set(r.username for r in results)))

    console = rich.get_console()
    table = Table(title="MA TRẬN KẾT QUẢ KIỂM TRA PHÂN QUYỀN", title_style="bold magenta", show_lines=True)
    table.add_column("USER / GROUP")
    for group in groups: table.add_column(group, justify="center")

    for user in users:
        row_data = [user]
        for group in groups:
            cell_results = [r for r in results if r.username == user and r.group == group]
        
            # Xét 4 trường hợp: rỗng, vi phạm luật bất biến, hợp lệ nếu tất cả ok, không hợp lệ nếu có ít nhất 1 fail
            if not cell_results: row_data.append("-")
            elif any([r.invariant_verdict for r in cell_results]): row_data.append("[yellow]![/yellow]")
            elif all([r.ok for r in cell_results]): row_data.append("[bold green]✓[/bold green]")
            else: row_data.append("[bold red]✗[/bold red]")
        table.add_row(*row_data)

    console.print(table)
    console.print(
    "\n[italic]Chú thích: "
    "[bold green]✓[/bold green] Trùng khớp Matrix | "
    "[bold red]✗[/bold red] Sai quyền | "
    "[bold yellow]![/bold yellow] Vi phạm luật cấm[/italic]\n"
    )


def write_junit(results: List[ProbeResult], path: str):
    """
    Xuất kết quả kiểm thử ra định dạng JUnit XML cho CI/CD.
    """
    if not results:
        print("[*] Không có dữ liệu để xuất ra JUnit XML.")
        return

    total_tests = len(results)
    total_failures = len([r for r in results if not r.ok])
    testsuites = ET.Element("testsuites")
    testsuite = ET.SubElement(testsuites, "testsuite", name="RBAC Matrix Tests",
                              tests=str(total_tests), failures=str(total_failures))

    for r in results:
        classname = r.group
        testname = f"{r.username} {r.method} {r.path}"
        testcase = ET.SubElement(testsuite, "testcase", classname=classname, name=testname)

        # Trường hợp không khớp ma trận hoặc vi phạm luật bất biến, thêm thẻ <failure>
        if not r.ok:
            if r.invariant_verdict:
                ET.SubElement(testcase, "failure", message="Oracle Invariant Violation", type="OracleInvariantError"
                ).text = f"Vi phạm luật bất biến: {r.invariant_verdict}"
            else:
                ET.SubElement(testcase, "failure", message="RPAC Matrix Mismatch", type="MatrixMismatchError"
                ).text = f"Ma trận yêu cầu: {r.matrix_expected} / Hệ thống trả về: {r.actual_allow}"
    
    tree = ET.ElementTree(testsuites)
    ET.indent(tree, space="    ",)
    with open(path, "wb") as f:
        tree.write(f, encoding="utf-8", xml_declaration=True)
        print(f"[*] Kết quả kiểm thử đã được xuất ra file {path}")


