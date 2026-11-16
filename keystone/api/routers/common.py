"""Shared bits for routers."""

from datetime import date

from pydantic import BaseModel, ConfigDict


class In(BaseModel):
    """Request bodies reject unknown fields (no mass assignment)."""

    model_config = ConfigDict(extra="forbid")


def people_names(db) -> dict[int, str]:
    from keystone.core.auth import list_users

    return {u.id: u.display_name for u in list_users(db)}


def xlsx_response(data: bytes, filename: str):
    from fastapi.responses import Response

    return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def docx_response(data: bytes, filename: str):
    from fastapi.responses import Response

    return Response(data, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


__all__ = ["In", "people_names", "xlsx_response", "docx_response", "date"]
